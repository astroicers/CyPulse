# 部署規格書 (Deployment Specification)

| 欄位 | 內容 |
|------|------|
| **專案名稱** | CyPulse — 開源 EASM 資安曝險評級平台 |
| **版本** | v0.1.0 |
| **最後更新** | 2026-03-12 |
| **狀態** | Draft |
| **作者** | CyPulse 開發團隊 |
| **審閱者** | — |

---

## 1. 環境定義

### 1.1 環境清單

> CyPulse 為開源 CLI 工具，僅有兩種執行環境。

| 環境 | 用途 | 部署方式 | 說明 |
|------|------|----------|------|
| `local` | 本地開發與測試 | `pip install -e .` + 手動安裝工具 | 開發者用，需自行安裝 PD tools |
| `docker` | 生產執行（推薦） | `docker-compose up` | 封裝所有依賴，一鍵啟動 |

### 1.2 環境差異對照

| 項目 | Local | Docker |
|------|-------|--------|
| Python | 使用者自行安裝 3.10+ | 3.11（Image 內建） |
| PD Tools | 使用者自行安裝 | Image 預裝（Go binaries） |
| nmap / testssl.sh | 使用者自行安裝 | Image 預裝 |
| weasyprint + 字型 | 使用者自行安裝 | Image 預裝 + Noto Sans TC |
| 掃描結果儲存 | `./data/` | Volume mount `./data/` |
| 設定檔 | `config/config.yaml` | Volume mount 或環境變數 |
| Cron 排程 | Host crontab | Container crontab 或 host cron |

### 1.3 環境變數清單

> **安全規則**：API Key 禁止硬編碼，透過環境變數或 config.yaml 注入。

#### 應用程式設定

| 變數名 | 類型 | 必填 | 預設值 | 說明 |
|--------|------|------|--------|------|
| `CYPULSE_OUTPUT_DIR` | string | 否 | `./data` | 掃描結果輸出目錄 |
| `CYPULSE_CONFIG` | string | 否 | `config/config.yaml` | 設定檔路徑 |
| `CYPULSE_LOG_LEVEL` | string | 否 | `INFO` | 日誌等級：DEBUG/INFO/WARNING/ERROR |
| `CYPULSE_RATE_LIMIT` | int | 否 | `50` | 掃描速率限制（req/s） |
| `CYPULSE_TIMEOUT` | int | 否 | `300` | 單一工具最長執行時間（秒） |

#### 第三方 API

| 變數名 | 類型 | 必填 | 說明 |
|--------|------|------|------|
| `ABUSEIPDB_API_KEY` | string | 否 | AbuseIPDB API Key（M2 模組） |
| `HIBP_API_KEY` | string | 否 | Have I Been Pwned API Key（M6 模組） |
| `URLSCAN_API_KEY` | string | 否 | URLScan.io API Key（M7 模組） |

#### 通知設定

| 變數名 | 類型 | 必填 | 說明 |
|--------|------|------|------|
| `SLACK_WEBHOOK_URL` | string | 否 | Slack Incoming Webhook URL |
| `EMAIL_SMTP_HOST` | string | 否 | SMTP 伺服器位址 |
| `EMAIL_SMTP_PORT` | int | 否 | SMTP 埠號（預設 587） |
| `EMAIL_SMTP_USER` | string | 否 | SMTP 帳號 |
| `EMAIL_SMTP_PASS` | string | 否 | SMTP 密碼 |
| `EMAIL_FROM` | string | 否 | 寄件者地址 |
| `EMAIL_TO` | string | 否 | 收件者地址（逗號分隔） |
| `LINE_NOTIFY_TOKEN` | string | 否 | LINE Notify Token |

---

## 2. Container 規格

### 2.1 Base Image

```dockerfile
FROM python:3.11-slim AS base

# 選擇 slim 而非 alpine：
# - weasyprint 需要 cairo/pango 等 C libraries，Alpine 安裝複雜
# - 部分 Python security packages 需要 gcc 編譯
# - slim 提供更好的相容性，體積仍可控
```

### 2.2 Multi-Stage Build

```dockerfile
# ===================== Stage 1: PD Tools =====================
FROM golang:1.22-alpine AS pd-tools
RUN apk add --no-cache git

# 安裝 ProjectDiscovery 工具
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# ===================== Stage 2: Python Deps =====================
FROM python:3.11-slim AS deps
WORKDIR /app
COPY requirements.txt ./
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libffi-dev && \
    pip install --no-cache-dir -r requirements.txt && \
    apt-get purge -y gcc libffi-dev && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# ===================== Stage 3: Production =====================
FROM python:3.11-slim AS runner
WORKDIR /app

# 系統依賴（weasyprint + nmap + testssl.sh + 字型）
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
        dnsrecon \
        libcairo2 \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libgdk-pixbuf2.0-0 \
        fonts-noto-cjk \
        curl \
        && rm -rf /var/lib/apt/lists/*

# 安裝 testssl.sh
RUN curl -sL https://github.com/drwetter/testssl.sh/archive/refs/heads/3.2/main.tar.gz | \
    tar xz -C /opt/ && \
    ln -s /opt/testssl.sh-3.2-main/testssl.sh /usr/local/bin/testssl.sh

# 複製 PD tools
COPY --from=pd-tools /root/go/bin/subfinder /usr/local/bin/
COPY --from=pd-tools /root/go/bin/httpx /usr/local/bin/
COPY --from=pd-tools /root/go/bin/nuclei /usr/local/bin/
COPY --from=pd-tools /root/go/bin/dnsx /usr/local/bin/
COPY --from=pd-tools /root/go/bin/naabu /usr/local/bin/

# 複製 Python 依賴
COPY --from=deps /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=deps /usr/local/bin /usr/local/bin

# 安全：非 root 使用者
RUN groupadd -r cypulse && useradd -r -g cypulse cypulse && \
    mkdir -p /app/data /app/config && \
    chown -R cypulse:cypulse /app

# 複製應用程式
COPY --chown=cypulse:cypulse . .

USER cypulse

ENTRYPOINT ["python", "-m", "cypulse"]
CMD ["--help"]
```

### 2.3 Docker Compose

```yaml
version: '3.8'

services:
  cypulse:
    build: .
    image: ghcr.io/cypulse/cypulse:latest
    volumes:
      - ./data:/app/data           # 掃描結果持久化
      - ./config:/app/config       # 設定檔
    env_file:
      - .env                       # API Keys 等敏感設定
    environment:
      - CYPULSE_OUTPUT_DIR=/app/data
      - CYPULSE_LOG_LEVEL=INFO
```

**使用方式：**

```bash
# 一鍵掃描
docker-compose run --rm cypulse scan example.com

# 產出報告
docker-compose run --rm cypulse report data/example.com/2026-03-12T020000

# 差異比對
docker-compose run --rm cypulse diff data/example.com/old data/example.com/new
```

### 2.4 Resource 建議

| 項目 | 最低需求 | 建議配置 |
|------|----------|----------|
| CPU | 2 vCPU | 4 vCPU |
| RAM | 2 GB | 4 GB |
| Disk | 10 GB | 50 GB（含歷史掃描結果） |
| Network | 10 Mbps | 100 Mbps |

---

## 3. CI/CD Pipeline

### 3.1 Pipeline 架構（GitHub Actions）

```
PR 建立 / Push
│
├── [自動觸發] CI Pipeline
│   ├── Stage 1: Code Quality
│   │   ├── Lint（flake8 + black --check）
│   │   ├── Type Check（mypy）
│   │   └── Security Scan（pip-audit）
│   │
│   ├── Stage 2: Testing
│   │   ├── Unit Tests（pytest）
│   │   └── Coverage Report（門檻：80%）
│   │
│   └── Stage 3: Build Verification
│       └── Docker Build（確認 Image 可成功建置）
│
Push to main
│
└── [自動觸發] Release Pipeline
    ├── Build Docker Image（with SHA tag + latest）
    ├── Push to ghcr.io/cypulse/cypulse
    └── 若有 version tag → 建立 GitHub Release
```

### 3.2 自動化測試門檻

| 測試類型 | 工具 | 通過門檻 | 失敗行為 |
|----------|------|----------|----------|
| Lint | flake8 + black | 0 Error | Block PR |
| Type Check | mypy | 0 Error | Block PR |
| Unit Tests | pytest | 全通過 | Block PR |
| Coverage | pytest-cov | 整體 > 80% | Block PR |
| Security | pip-audit | 0 Critical/High | Block PR |
| Docker Build | docker build | 成功 | Block PR |

### 3.3 GitHub Actions Workflow 範例

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install flake8 black mypy
      - run: black --check .
      - run: flake8 .
      - run: mypy cypulse/

  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -e ".[dev]"
      - run: pytest --cov=cypulse --cov-fail-under=80

  docker:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t cypulse:test .
```

---

## 4. 監控與告警

> CyPulse 為 CLI 工具，非長時間運行的服務。無需傳統的 APM / Metrics 監控。

### 4.1 日誌

- **格式**：Structured JSON logging（Python `structlog`）
- **位置**：stdout（Docker logs）+ `logs/cypulse.log`（可選）
- **等級**：INFO（預設），可透過 `CYPULSE_LOG_LEVEL` 調整

### 4.2 掃描狀態追蹤

每次掃描完成後輸出摘要至 stdout：

```
[SCAN COMPLETE] domain=example.com score=78 grade=C duration=1102s modules=7/7 findings=47
```

### 4.3 Cron 排程監控

透過 cron job 的 log 輸出監控排程執行狀態：

```bash
# crontab -e
0 2 * * 0  docker-compose run --rm cypulse scan example.com >> /var/log/cypulse-cron.log 2>&1
```

---

## 5. 災難復原（Disaster Recovery）

> CyPulse 為開源 CLI 工具，使用者自行管理資料。

### 5.1 資料備份

| 資料類型 | 備份建議 | 說明 |
|----------|----------|------|
| 掃描結果（`data/`） | 使用者自行備份 | JSON + HTML/PDF 檔案 |
| 設定檔（`config/`） | 納入版本控制 | 排除含 API Key 的檔案 |
| Docker Image | ghcr.io 自動保存 | 每次 push to main 自動建置 |

### 5.2 還原方式

```bash
# 還原 Docker 環境
docker pull ghcr.io/cypulse/cypulse:latest

# 還原掃描結果
# 將備份的 data/ 目錄掛載至 container
docker-compose up -d
```

### 5.3 已知風險與應對

| 風險 | 影響 | 應對方案 |
|------|------|----------|
| PD 工具停止維護 | 無法更新 binary | 鎖定最後穩定版本，社群 fork |
| HIBP/AbuseIPDB API 關閉免費額度 | M2/M6 模組失效 | 降級為離線資料集比對 |
| Docker Hub rate limit | Image pull 失敗 | 使用 ghcr.io 作為主要 registry |

---

## 附錄

### A. 快速部署檢查清單

**首次部署前確認：**

- [ ] Docker 20.10+ 已安裝
- [ ] docker-compose v2 已安裝
- [ ] `.env` 檔案已建立（至少 `ABUSEIPDB_API_KEY`）
- [ ] `config/targets.yaml` 已設定目標 domain
- [ ] `data/` 目錄存在且有寫入權限
- [ ] 網路可連線至目標 domain
- [ ] 已確認目標 domain 的掃描授權

### B. requirements.txt 主要依賴

```
checkdmarc>=5.0
dnstwist>=20230918
h8mail>=2.5
jinja2>=3.1
weasyprint>=60.0
pyyaml>=6.0
requests>=2.31
structlog>=23.1
click>=8.1           # CLI framework（備選 argparse）
```

### C. 設定檔範例（config/config.yaml.example）

```yaml
# CyPulse 設定檔
# 複製為 config.yaml 並填入實際值

# 掃描設定
scan:
  rate_limit: 50          # 掃描速率（req/s）
  timeout: 300            # 單一工具 timeout（秒）
  modules: [M1, M2, M3, M4, M5, M6, M7]  # 啟用的模組

# API Keys
api_keys:
  abuseipdb: ""           # https://www.abuseipdb.com/account/api
  hibp: ""                # https://haveibeenpwned.com/API/Key
  urlscan: ""             # https://urlscan.io/docs/api/

# 通知設定
notifications:
  slack:
    webhook_url: ""
  email:
    smtp_host: ""
    smtp_port: 587
    smtp_user: ""
    smtp_pass: ""
    from: ""
    to: []
  line:
    notify_token: ""

# 報告設定
report:
  language: zh-TW
  font: "Noto Sans TC"
  logo: ""                # 自訂 Logo 路徑（選填）
```

### D. 變更歷史

| 版本 | 日期 | 變更摘要 | 作者 |
|------|------|----------|------|
| v0.1.0 | 2026-03-12 | 初版建立 | CyPulse 開發團隊 |

### E. 相關文件

- [`SRS.md`](./SRS.md) — 軟體需求規格書
- [`SDS.md`](./SDS.md) — 軟體設計規格書
- [`architecture.md`](./architecture.md) — 系統架構文件
- [`docs/adr/`](./adr/) — 架構決策記錄
