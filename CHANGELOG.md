# Changelog

所有重要變更記錄在此，格式依循 [Keep a Changelog](https://keepachangelog.com/zh-TW/1.0.0/)。

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
