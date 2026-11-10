#!/usr/bin/env python3
"""產出 CI Release 的 manifest.json（第 5.4、6.4 節）：來源 SHA、工具版本、漏洞資料庫版本與檔案雜湊。"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

FILES = ["sbom.cdx.json", "trivy-sbom.json"]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    target_sha = os.environ.get("TARGET_SHA", "")
    if not re.fullmatch(r"[0-9a-f]{40}", target_sha):
        print("ci_manifest: invalid TARGET_SHA", file=sys.stderr)
        return 2
    missing = [f for f in FILES if not Path(f).is_file()]
    trivy = {}
    if Path("trivy-version.json").is_file():
        trivy = json.loads(Path("trivy-version.json").read_text(encoding="utf-8") or "{}")
    db = trivy.get("VulnerabilityDB") or {}
    sbom = json.loads(Path("sbom.cdx.json").read_text(encoding="utf-8")) if Path("sbom.cdx.json").is_file() else {}
    sbom_tool = next((t for t in (sbom.get("metadata", {}).get("tools", {}).get("components") or [])), {})
    manifest = {
        "schema_version": 1,
        "kind": "ci-release",
        "target_sha": target_sha,
        "run_id": os.environ.get("RUN_ID"),
        "run_attempt": os.environ.get("RUN_ATTEMPT"),
        "deployment_id": os.environ.get("DEPLOYMENT_ID"),
        "service_ids": json.loads(os.environ.get("DEPLOY_SERVICES", "[]")),
        "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool_version": {"sbom_generator": sbom_tool.get("name"), "sbom_generator_version": sbom_tool.get("version"),
                         "trivy": trivy.get("Version")},
        "database_revision": {"trivy_db_updated_at": db.get("UpdatedAt"), "trivy_db_version": db.get("Version")},
        "files": {f: sha256(Path(f)) for f in FILES if Path(f).is_file()},
        "status": "failed" if missing else "ok",
        "missing": missing,
    }
    Path("manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False))
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
