# Changelog

## 1.0.1 — 2026-11-10
- CI：SBOM 改由與掃描相同版本的 Trivy 產生（syft 產生的 SBOM 根元件類型為 file，Trivy 0.57.1 無法解析，首次 CI 失敗）；三次 Trivy 共用快取，manifest 才記得到漏洞資料庫版本
- `scripts/reset-demo.sh` 標記為可執行
- `baseline` tag 移到本版本：重設會還原所有受追蹤檔案，基準必須包含可用的 CI；第 5.2 節的刻意問題不變

## 1.0.0 — 2026-11-09
- 受評估的假設環境：storefront、member-api、internal-tool、marketing-site、brand-app
- 第 5.2 節 25 項刻意問題對應的清冊、快照與訊號
- CI（SBOM、Deployment、Release manifest）與 PR 把關
- Demo 重設腳本 `scripts/reset-demo.sh`
