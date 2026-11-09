#!/usr/bin/env python3
"""PR 把關（觸發 ①，第 5.5 節）。只用工具與規則，不用 LLM。

執行方式：workflow 從受保護的 base SHA 取出本檔再執行，PR 無法改寫自己的把關規則。
環境變數：BASE_SHA、HEAD_SHA（40 字元十六進位）、SCANNER_MODE（docker|local|none）、
          GITLEAKS_IMAGE、TRIVY_IMAGE、OUT_DIR。
結束碼：0 通過；1 檢查失敗（新增高風險）；2 掃描本身失敗或缺必要輸入（不當作零發現）。
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SERVICES_DIR = "services/"
SHARED_PATHS = ("package-lock.json", "package.json", ".gitleaks.toml", ".security/", "scripts/")
DB_PORTS = {"3306", "5432", "6379", "27017"}


class ScanError(RuntimeError):
    pass


def run(cmd: list[str], *, cwd: str | None = None, ok_codes=(0,)) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if proc.returncode not in ok_codes:
        raise ScanError(f"{' '.join(cmd[:3])}… exit {proc.returncode}: {proc.stderr.strip()[:400]}")
    return proc


def git(*args: str, cwd: str | None = None) -> str:
    return run(["git", *args], cwd=cwd).stdout


def changed_files(base: str, head: str) -> list[str]:
    return [p for p in git("diff", "--name-only", f"{base}...{head}").splitlines() if p]


def services_in_scope(files: list[str], all_services: list[str]) -> list[str]:
    if any(f.startswith(SHARED_PATHS) or "/" not in f for f in files):
        return all_services  # 共用設定或根目錄檔案變動：展開所有服務
    scope = {f.split("/")[1] for f in files if f.startswith(SERVICES_DIR) and f.count("/") >= 2}
    return sorted(s for s in scope if s in all_services)


def list_services(root: str) -> list[str]:
    d = Path(root) / "services"
    return sorted(p.name for p in d.iterdir() if p.is_dir()) if d.is_dir() else []


# ---------------------------------------------------------------- scanners
def gitleaks_new_secrets(base: str, head: str, config: Path, mode: str, image: str, out: Path) -> list[dict]:
    """只掃 PR 的 commits（BASE..HEAD），使用 base 的 .gitleaks.toml，結果遮蔽。"""
    report = out / "gitleaks.json"
    args = ["detect", "--source", "/repo" if mode == "docker" else ".", "--log-opts", f"{base}..{head}",
            "--config", "/cfg/gitleaks.toml" if mode == "docker" else str(config),
            "--redact", "--report-format", "json", "--report-path",
            "/out/gitleaks.json" if mode == "docker" else str(report), "--exit-code", "0", "--no-banner"]
    if mode == "docker":
        cmd = ["docker", "run", "--rm", "-v", f"{os.getcwd()}:/repo", "-v", f"{config.parent}:/cfg:ro",
               "-v", f"{out}:/out", image, *args]
    elif mode == "local":
        cmd = ["gitleaks", *args]
    else:
        raise ScanError("SCANNER_MODE=none：缺少 gitleaks，無法完成把關")
    run(cmd)
    if not report.exists():
        raise ScanError("gitleaks 沒有產出報告")
    data = json.loads(report.read_text(encoding="utf-8") or "[]")
    return [{"rule": f.get("RuleID"), "path": f.get("File"), "line": f.get("StartLine"), "commit": (f.get("Commit") or "")[:12]}
            for f in data]


def trivy_vulns(path: str, mode: str, image: str) -> dict[tuple[str, str], float]:
    if not Path(path).exists():
        return {}
    if mode == "docker":
        cmd = ["docker", "run", "--rm", "-v", f"{Path(path).resolve()}:/scan:ro", image,
               "fs", "--scanners", "vuln", "--format", "json", "--quiet", "/scan"]
    elif mode == "local":
        cmd = ["trivy", "fs", "--scanners", "vuln", "--format", "json", "--quiet", path]
    else:
        raise ScanError("SCANNER_MODE=none：缺少 trivy")
    data = json.loads(run(cmd).stdout or "{}")
    result: dict[tuple[str, str], float] = {}
    for r in data.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            score = 0.0
            for src in (v.get("CVSS") or {}).values():
                score = max(score, float(src.get("V3Score") or 0))
            result[(v.get("PkgName", ""), v.get("VulnerabilityID", ""))] = score
    return result


def manifest_debuggable(text: str) -> bool:
    return bool(re.search(r'android:debuggable\s*=\s*"true"', text))


def new_public_db_ingress(base_tf: str, head_tf: str) -> list[str]:
    def rules(tf: str) -> set[str]:
        found = set()
        for block in re.findall(r"ingress\s*\{(.*?)\}", tf, flags=re.S):
            port = re.search(r"from_port\s*=\s*(\d+)", block)
            if port and port.group(1) in DB_PORTS and "0.0.0.0/0" in block:
                found.add(port.group(1))
        return found
    return sorted(rules(head_tf) - rules(base_tf))


def show(rev: str, path: str) -> str:
    proc = subprocess.run(["git", "show", f"{rev}:{path}"], capture_output=True, text=True, encoding="utf-8")
    return proc.stdout if proc.returncode == 0 else ""


# ---------------------------------------------------------------- main
def main() -> int:
    base, head = os.environ.get("BASE_SHA", ""), os.environ.get("HEAD_SHA", "")
    if not (SHA_RE.match(base) and SHA_RE.match(head)):
        print("pr-gate: BASE_SHA／HEAD_SHA 格式錯誤", file=sys.stderr)
        return 2
    mode = os.environ.get("SCANNER_MODE", "docker")
    gl_image = os.environ.get("GITLEAKS_IMAGE", "zricethezav/gitleaks:v8.21.2")
    tv_image = os.environ.get("TRIVY_IMAGE", "aquasec/trivy:0.57.1")
    out = Path(os.environ.get("OUT_DIR", "pr-gate-out")).resolve()
    out.mkdir(parents=True, exist_ok=True)

    blocking: list[str] = []
    notes: list[str] = []
    errors: list[str] = []

    try:
        files = changed_files(base, head)
        all_services = list_services(".")
        scope = services_in_scope(files, all_services)

        # 掃描規則一律取自 base SHA
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "gitleaks.toml"
            base_cfg = show(base, ".gitleaks.toml")
            if not base_cfg:
                raise ScanError("base SHA 沒有 .gitleaks.toml")
            cfg.write_text(base_cfg, encoding="utf-8")
            for s in gitleaks_new_secrets(base, head, cfg, mode, gl_image, out):
                blocking.append(f"新增金鑰：`{s['path']}` 第 {s['line']} 行（規則 {s['rule']}，commit {s['commit']}）"
                                "｜建議：移除並撤銷該金鑰，改用 Secrets Manager｜規格 5.5")

        if scope:
            with tempfile.TemporaryDirectory() as wt:
                git("worktree", "add", "--detach", wt, base)
                try:
                    for svc in scope:
                        head_v = trivy_vulns(f"services/{svc}", mode, tv_image)
                        base_v = trivy_vulns(f"{wt}/services/{svc}", mode, tv_image)
                        for (pkg, vid), score in sorted(head_v.items()):
                            if score >= 9 and base_v.get((pkg, vid), -1) < score:
                                blocking.append(f"新增 CVSS {score} 套件問題：{svc} 的 {pkg}（{vid}）｜建議：升級到修補版本｜規格 5.5")
                            elif (pkg, vid) not in base_v:
                                notes.append(f"新增套件問題：{svc} 的 {pkg}（{vid}，CVSS {score}）")
                finally:
                    git("worktree", "remove", "--force", wt)

        if any(f.startswith("infra/terraform/") for f in files):
            for port in new_public_db_ingress(show(base, "infra/terraform/main.tf"), show(head, "infra/terraform/main.tf")):
                blocking.append(f"新增對外開放的資料庫連線（port {port}，0.0.0.0/0）｜建議：限制來源網段｜規格 5.5")
            notes.append("Terraform 有變動：Checkov 結果見 artifact（非阻擋項目只列出）")

        manifest = "services/brand-app/android/app/src/main/AndroidManifest.xml"
        if manifest in files and manifest_debuggable(show(head, manifest)) and not manifest_debuggable(show(base, manifest)):
            blocking.append("新增 `android:debuggable=\"true\"`｜建議：正式版關閉 debuggable｜規格 5.5")
    except ScanError as exc:
        errors.append(str(exc))

    lines = ["## pr-gate 把關結果", ""]
    if errors:
        lines += ["**掃描失敗（不當作零發現，檢查失敗）**", *[f"- {e}" for e in errors], ""]
    lines += ["**擋下的問題**" if blocking else "沒有新增的高風險問題。", *[f"- {b}" for b in blocking], ""]
    if notes:
        lines += ["**其他問題（不擋下）**", *[f"- {n}" for n in notes]]
    (out / "comment.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (out / "result.json").write_text(json.dumps({"blocking": blocking, "notes": notes, "errors": errors},
                                                ensure_ascii=False, indent=2), encoding="utf-8")
    print("\n".join(lines))
    if errors:
        return 2
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
