#!/usr/bin/env bash
# Demo 重設（第 5.7 節）。只供使用者手動執行，不由 Agent 或網站呼叫。
# 用法：BASELINE_SHA=<README 記錄的 baseline commit SHA> scripts/reset-demo.sh
# 行為：從最新 main 開唯一分支 demo-reset-<timestamp>，把受追蹤檔案還原成 baseline，commit 並開 PR。
#       不刪除未追蹤檔案、不改寫 main 歷史、不自動繞過分支保護。
set -euo pipefail

EXPECTED_REPO="shopsaas-demo-platform"
TAG="baseline"

fail() { echo "reset-demo: $*" >&2; exit 1; }

[[ "${BASELINE_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || fail "請以環境變數 BASELINE_SHA 提供 40 字元的 baseline commit SHA（見 README）"

root="$(git rev-parse --show-toplevel 2>/dev/null)" || fail "不在 Git Repo 內"
cd "$root"

remote_url="$(git remote get-url origin 2>/dev/null)" || fail "找不到 origin remote"
case "$remote_url" in
  */"$EXPECTED_REPO"|*/"$EXPECTED_REPO".git|*:"$EXPECTED_REPO".git) ;;
  *) case "$remote_url" in *"/$EXPECTED_REPO"*) ;; *) fail "origin 不是 $EXPECTED_REPO：$remote_url" ;; esac ;;
esac

[[ -z "$(git status --porcelain)" ]] || fail "工作目錄不乾淨，請先 commit 或 stash"

git fetch --quiet origin main --tags
tag_sha="$(git rev-parse --verify "refs/tags/$TAG^{commit}" 2>/dev/null)" || fail "找不到 $TAG tag"
[[ "$tag_sha" == "$BASELINE_SHA" ]] || fail "$TAG tag（$tag_sha）與受信任的 BASELINE_SHA 不一致，停止"

branch="demo-reset-$(date -u +%Y%m%d%H%M%S)"
git switch --quiet -c "$branch" origin/main
git restore --source="$BASELINE_SHA" --staged --worktree -- .

if git diff --cached --quiet; then
  echo "main 已與 baseline 相同，不需要重設。"
  git switch --quiet - && git branch --quiet -D "$branch"
  exit 0
fi

echo "== 將還原的變更 =="
git diff --cached --stat
read -r -p "確認以上變更並 commit、push、開 PR？[y/N] " answer
[[ "$answer" == "y" || "$answer" == "Y" ]] || { echo "已取消；分支 $branch 保留在本機。"; exit 1; }

git commit --quiet -m "demo: reset to baseline $BASELINE_SHA"
git push --quiet -u origin "$branch"

if command -v gh >/dev/null 2>&1; then
  gh pr create --base main --head "$branch" \
    --title "demo: 還原到 baseline" \
    --body "由 scripts/reset-demo.sh 產生。還原會把 DEMO-FAKE 假金鑰加回，pr-gate 應該擋下；請檢查 diff 後依 ruleset 手動授權合併。"
else
  echo "已 push $branch；請手動在 GitHub 開 PR。"
fi
echo "注意：pr-gate 預期會失敗（假金鑰被加回）。請檢查 PR 後，依 ruleset 由你手動授權合併；本腳本不會繞過分支保護。"
