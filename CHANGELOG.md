# Changelog

所有重要變更記錄在此，格式依循 [Keep a Changelog](https://keepachangelog.com/zh-TW/1.0.0/)。

---

## [0.2.0] - 2026-04-17

### Added

- **M8 雲端資產暴露模組**（S3Scanner）— 偵測 S3 / GCS / Azure Blob 公開 bucket（見 [ADR-005](docs/adr/ADR-005-cloud-exposure-module.md)）
- **M1 testssl.sh TLS 深度掃描**（憑證、弱 cipher、HSTS）
- **M2 IP-API.com ASN/ISP 可疑性檢查**（免費 API，無需 key）
- **補救建議擴充至 9 項**（涵蓋八大模組高頻 finding）
- **Notifier 整合測試補齊**：`send_alerts`、SMTP 錯誤、HTTP 非 200 覆蓋
- **pipeline 埠去重**：避免 naabu 重複回傳相同 port
- **flake8 設定檔** `.flake8`（max-line-length=100，對齊 black）

### Changed

- **評分權重重新平衡**（見 ADR-005）：M5 10→8%、M7 5→3%、新增 M8 4%；八大總和仍為 100%
- **等級閾值線性化**（見 [ADR-004](docs/adr/ADR-004-scoring-dedup-and-remediation.md)）：A(90–100)、B(75–89)、C(60–74)、D(0–59)
- **M1 per-header-type 彙總扣分**：每種 header 最多扣 5 分並以單一 finding 呈現，避免 findings 爆炸
- **pytest 264 測試、整體覆蓋率 85%**

### Fixed

- **M1 httpx security headers 永遠為空的失真**：`httpx_tool.py` 加 `-irh` 並解析 PD httpx snake_case header dict，修復前 M1 永遠 0 分
- **subprocess retry backoff 上限**：`max_backoff=60s` 避免無限增長
- **測試檔 F401/E303 lint 違規**：移除 11 筆未使用 import、2 筆多餘空行

### Known Issues / Technical Debt

- D 等級範圍（0–59）仍偏大，未再細分（見 ADR-002）
- weasyprint PDF 在 ARM 架構有字型相容性問題（需 Noto CJK）
- HIBP 免費 fallback 有 rate limit

---

## [0.1.0] - 2026-03-16

### Added

**資產探勘（Layer 1）**
- subfinder / amass — 子網域被動列舉
- dnsx — DNS 解析驗證（過濾無效子網域）
- httpx — HTTP 存活偵測與 Security Header 採集
- naabu — 埠掃描（Top 1000 + 自訂埠號）

**七大安全分析模組（Layer 2）**
- M1 網站服務安全（Security Headers / TLS / Nuclei 漏洞掃描）25%
- M2 IP 信譽（AbuseIPDB 付費 + AlienVault OTX 免費 fallback）15%
- M3 網路服務安全（高風險埠偵測 / Nmap 服務識別）20%
- M4 DNS 安全（DNSSEC / Zone Transfer / SPF-DNS 驗證）15%
- M5 郵件安全（SPF / DKIM / DMARC 完整驗證）10%
- M6 暗網憑證外洩（LeakCheck 付費 + HIBP 免費 fallback）10%
- M7 偽冒域名偵測（dnstwist 相似域名掃描）5%

**評分引擎（Layer 3）**
- 七維度加權評分演算法，0-100 分，A/B/C/D 等級
- 見 [ADR-002](docs/adr/ADR-002-scoring-algorithm.md) 設計決策

**報告與輸出**
- 繁體中文 HTML / PDF 報告（Jinja2 + weasyprint）
- JSON / CSV 原始資料匯出
- 掃描差異比對，自動標記新增/解除的風險項目

**通知整合**
- Slack webhook 通知
- Email 通知
- LINE Notify

**免費 API Fallback**
- M2 / M6 在無 API Key 時自動降級至免費替代源
- 見 [ADR-003](docs/adr/ADR-003-api-fallback-free-sources.md) 設計決策

**基礎設施**
- Docker 容器化一鍵部署（含所有掃描工具）
- pytest 229+ 測試，覆蓋率 ≥ 80%
- GitHub Flow 分支策略 + Conventional Commits

### Known Issues / Technical Debt

- D 等級範圍（0-69）過大，未細分（見 ADR-002）
- weasyprint PDF 在 ARM 架構有字型相容性問題（需安裝 Noto CJK 字型）
- HIBP 免費 fallback 有 rate limit，大量掃描時速度較慢
