# CyPulse

開源 EASM（External Attack Surface Management）資安曝險評級平台。

以 100% 開源工具實作八維度資安掃描與評級，產出 0-100 量化分數與 A/B/C/D 等級，
輸出繁體中文 HTML / PDF / CSV 報告。

---

## 功能特色

**資產探勘（5 工具聯動）**
- subfinder / amass — 子網域被動列舉
- dnsx — DNS 解析驗證
- httpx — HTTP 存活、Security Header 採集（`-irh`）、TLS 版本偵測
- naabu — 埠掃描（結果去重）

**八大安全分析模組**

| 模組 | 維度 | 權重 | 滿分 |
|------|------|------|------|
| M1 | Web Security（Security Header / TLS / Nuclei / testssl.sh） | 25% | 25 |
| M2 | IP Reputation（AbuseIPDB + IP-API ASN/ISP + Shodan + GreyNoise） | 15% | 15 |
| M3 | Network Security（高風險埠 / Nmap + vulners） | 20% | 20 |
| M4 | DNS Security（DNSSEC / Zone Transfer） | 15% | 15 |
| M5 | Email Security（SPF / DKIM / DMARC） | 8% | 8 |
| M6 | Dark Web Exposure（HIBP + LeakCheck fallback） | 10% | 10 |
| M7 | Fake Domains（dnstwist） | 3% | 3 |
| M8 | Cloud Exposure（S3Scanner — S3 / GCS / Azure Blob） | 4% | 4 |

> 權重分配見 [ADR-005](docs/adr/ADR-005-cloud-exposure-module.md)；等級閾值線性化
> 見 [ADR-004](docs/adr/ADR-004-scoring-dedup-and-remediation.md)：
> A(90–100)、B(75–89)、C(60–74)、D(0–59)。

**其他**
- 加權評分演算法（0-100 分，A/B/C/D 等級）
- 繁體中文 HTML / PDF 報告
- JSON / CSV 原始資料匯出
- 掃描差異比對與告警
- Slack / Email / LINE 通知
- Docker 容器化一鍵部署

---

## 安裝

### Docker（推薦）

```bash
git clone https://github.com/your-org/cypulse.git
cd cypulse
cp .env.example .env       # 填入 API Key
docker-compose build
docker-compose run --rm cypulse scan example.com
```

### 本機安裝

```bash
# 前置需求：Python 3.10+、ProjectDiscovery 工具（subfinder/httpx/dnsx/naabu）、nmap
pip install -e .
cypulse --help
```

---

## 快速開始

```bash
cypulse scan example.com
```

輸出範例：

```
[CyPulse] 開始掃描 example.com...
[CyPulse] Phase 1: 資產探勘...
[CyPulse]   子網域: 12, 存活: 10, HTTP: 8
[CyPulse] Phase 2: 風險分析...
[CyPulse]   完成 8 個模組分析
[CyPulse] Phase 3: 評分...
[CyPulse]   總分: 78/100 (B)
[CyPulse] Phase 4: 報告產出...
[CyPulse]   HTML: data/example.com/20260417_020000/report.html
[CyPulse]   PDF: data/example.com/20260417_020000/report.pdf
[CyPulse]   CSV: 2 files

[SCAN COMPLETE] domain=example.com score=78 grade=B duration=1180s modules=8/8 findings=52
[CyPulse] 結果儲存於: data/example.com/20260417_020000
```

---

## CLI 指令

### `cypulse scan <domain>`

執行完整掃描（探勘 + 分析 + 評分 + 報告）。

```bash
cypulse scan example.com                        # 完整掃描（M1–M8）
cypulse scan example.com --modules M1,M5        # 僅執行指定模組
cypulse scan example.com --output ./results     # 指定輸出目錄
```

### `cypulse report <scan_dir>`

以既有掃描結果重新產出報告。

```bash
cypulse report data/example.com/20260312_020000              # HTML（預設）
cypulse report data/example.com/20260312_020000 -f pdf       # PDF
cypulse report data/example.com/20260312_020000 -f all       # 全部格式
```

### `cypulse diff <dir1> <dir2>`

比較兩次掃描結果差異。

```bash
cypulse diff data/example.com/20260301_020000 data/example.com/20260312_020000
```

---

## 設定

### API Key

複製 `.env.example` 為 `.env` 並填入：

```bash
ABUSEIPDB_API_KEY=your_key    # M2 IP Reputation
HIBP_API_KEY=your_key         # M6 Dark Web
URLSCAN_API_KEY=your_key      # 選用
SLACK_WEBHOOK_URL=https://... # 選用，Slack 通知
```

或使用 `config/config.yaml`（參考 `config/config.yaml.example`）。

---

## 專案結構

```
cypulse/
├── cli.py                  # CLI 入口
├── discovery/              # 資產探勘（subfinder/amass/dnsx/httpx/naabu/web_sources）
├── analysis/               # 八大安全分析模組（M1–M8）
├── scoring/                # 加權評分引擎
├── report/                 # HTML/PDF/CSV 報告產出
│   └── templates/          # Jinja2 報告模板
├── automation/             # 差異比對、通知
│   ├── diff.py
│   └── notifier.py
├── remediation/            # 補救建議 playbooks（9 項）
├── models/                 # 資料模型（dataclass）
└── utils/                  # 通用工具（sanitize / subprocess retry / logging）
```

---

## 開發

```bash
pip install -e ".[dev]"
make test                   # 執行測試
make lint                   # 程式碼檢查
make coverage               # 測試覆蓋率
```

---

## 授權

MIT License

---

## 相關文件

| 文件 | 說明 |
|------|------|
| [SRS.md](docs/SRS.md) | 軟體需求規格書 |
| [SDS.md](docs/SDS.md) | 軟體設計規格書 |
| [DEPLOY_SPEC.md](docs/DEPLOY_SPEC.md) | 部署規格書 |
| [architecture.md](docs/architecture.md) | 架構概覽 |
| [ADR-001](docs/adr/ADR-001-initial-technology-stack.md) | 技術棧選型決策 |
| [ADR-002](docs/adr/ADR-002-scoring-algorithm.md) | 評分演算法設計決策 |
| [ADR-003](docs/adr/ADR-003-api-fallback-free-sources.md) | API Fallback 機制決策 |
| [ADR-004](docs/adr/ADR-004-scoring-dedup-and-remediation.md) | 評分去重、等級線性化與補救建議設計 |
| [ADR-005](docs/adr/ADR-005-cloud-exposure-module.md) | M8 雲端資產暴露模組設計決策 |
| [ADR-006](docs/adr/ADR-006-source-resilience-and-confidence.md) | 來源級韌性追蹤與信心分數 |
| [ADR-007](docs/adr/ADR-007-scan-lifecycle-and-progress.md) | 掃描 Lifecycle + 進度顯示 + Ctrl-C/timeout |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | 常見問題排查 |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 貢獻指南 |
| [CHANGELOG.md](CHANGELOG.md) | 版本變更記錄 |
