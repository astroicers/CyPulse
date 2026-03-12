# 軟體需求規格書 (Software Requirements Specification)

| 欄位 | 內容 |
|------|------|
| **專案名稱** | CyPulse — 開源 EASM 資安曝險評級平台 |
| **版本** | v0.1.0 |
| **最後更新** | 2026-03-12 |
| **狀態** | Draft |
| **作者** | CyPulse 開發團隊 |
| **審閱者** | — |

---

## 1. 目的與範圍（Purpose & Scope）

### 1.1 文件目的

本文件描述 CyPulse 開源 EASM（External Attack Surface Management）資安曝險評級平台的完整軟體需求，作為開發、測試與驗收的基準依據。所有功能需求、非功能需求及使用者故事均應可追溯至本文件。

### 1.2 專案範圍

CyPulse 目標是以 100% 開源工具，建立完整的 EASM 資安曝險評級能力。透過自動化流水線整合子網域探勘、漏洞掃描、暗網監控、釣魚偵測等七大面向，輸出可量化的資安曝險分數與報告。

**範圍內（In Scope）：**

- 子網域被動列舉與資產探勘（subfinder / amass / dnsx / httpx / naabu）
- 七大安全分析模組（網站安全、IP 信譽、網路服務、DNS 安全、郵件安全、暗網憑證、偽冒域名）
- 七維度加權評分演算法（0-100 分，A/B/C/D 等級）
- 繁體中文 HTML / PDF 報告輸出
- JSON / CSV 原始資料匯出
- 差異比對告警與通知（Slack / Email / LINE）
- Docker 容器化一鍵部署
- GitHub 開源發布

**範圍外（Out of Scope）：**

- Web 管理介面（本版僅 CLI + 報告）
- 資料庫儲存（使用 JSON 檔案）
- 使用者認證與多租戶
- 即時監控 Dashboard（Grafana 為選配）
- 主動式入侵測試（僅做被動/非侵入式掃描）
- 付費 API 整合（所有工具需為免費或有免費額度）
- 行動裝置 App

### 1.3 定義與縮寫

| 術語 | 定義 |
|------|------|
| EASM | External Attack Surface Management，外部攻擊面管理 |
| PD | ProjectDiscovery — 開源安全工具套件 |
| CyPulse Score | 七維度加權資安曝險評分（0-100） |
| Exposure Rating | 資安曝險等級（A/B/C/D） |
| SRS | Software Requirements Specification，軟體需求規格書 |
| FR | Functional Requirement，功能需求 |
| NFR | Non-Functional Requirement，非功能需求 |
| SPF | Sender Policy Framework，寄件者政策框架 |
| DKIM | DomainKeys Identified Mail，網域金鑰認證郵件 |
| DMARC | Domain-based Message Authentication，網域郵件驗證 |
| DNSSEC | DNS Security Extensions，DNS 安全擴充 |
| HIBP | Have I Been Pwned，憑證外洩查詢服務 |

---

## 2. 利害關係人（Stakeholders）

| 角色 | 代表人 | 職責 | 參與階段 |
|------|--------|------|----------|
| 開發者 / 維護者 | CyPulse 開發團隊 | 全棧開發、測試、文件 | 全程 |
| 資安分析師（目標使用者） | — | 使用 CyPulse 掃描與產出報告 | 需求、驗收 |
| IT 管理員（目標使用者） | — | 部署 CyPulse、差異比對監控 | 部署、維護 |
| 開源社群貢獻者 | — | 模組擴充、Bug 回報、PR | 實作、維護 |

---

## 3. 功能需求（Functional Requirements）

> 命名規則：`FR-NNN`，按模組分段

### 3.1 資產探勘模組（FR-100）

| ID | 需求描述 | 優先級 | 對應 ROADMAP | 驗收標準 |
|----|----------|--------|--------------|----------|
| FR-101 | 系統應支援透過 subfinder + amass 進行子網域被動列舉，並合併去重輸出 | Must Have | M1 | 輸入 domain 後產出去重子網域清單（JSON），數量 > 0 |
| FR-102 | 系統應透過 dnsx 過濾存活的 DNS 解析記錄 | Must Have | M1 | 輸出僅包含有效 DNS 解析的子網域 |
| FR-103 | 系統應透過 httpx 驗證 HTTP 服務，取得 Title / Status / TLS / Security Headers | Must Have | M1 | 輸出 assets.json 包含 HTTP 服務詳細資訊 |
| FR-104 | 系統應透過 naabu 快速掃描常見 Port（80/443/8080/22/3306 等） | Must Have | M1 | 輸出開放 Port 清單，掃描時間 < 5 分鐘 per domain |
| FR-105 | 系統應提供一鍵探勘流水線，串接 subfinder → dnsx → naabu → httpx | Must Have | M1 | 執行單一指令完成全流程，輸出 assets.json |

### 3.2 安全分析模組（FR-200）

| ID | 需求描述 | 優先級 | 對應 ROADMAP | 驗收標準 |
|----|----------|--------|--------------|----------|
| FR-201 | M1 網站服務安全：整合 nuclei HTTP 模板掃描（misconfig / exposures），檢測 TLS 版本與 Security Headers | Must Have | M2 | 輸出 module_M1.json，含弱點清單與扣分明細 |
| FR-202 | M2 IP 信譽：查詢 AbuseIPDB API 與 Spamhaus DROP list，判定 IP 黑名單/灰名單狀態 | Must Have | M2 | 輸出 module_M2.json，每個 IP 含信譽狀態 |
| FR-203 | M3 網路服務安全：使用 nmap + nuclei CVE 模板掃描高危 Port 與已知漏洞 | Must Have | M2 | 輸出 module_M3.json，含 CVE 編號與嚴重等級 |
| FR-204 | M4 網域系統安全：檢查 SOA/MX/DNSSEC 設定，偵測 Zone Transfer 漏洞 | Should Have | M2 | 輸出 module_M4.json，含 DNSSEC 與 Zone Transfer 檢測結果 |
| FR-205 | M5 郵件安全：使用 checkdmarc 檢測 SPF/DKIM/DMARC 設定 | Should Have | M2 | 輸出 module_M5.json，含三項郵件安全機制檢測結果 |
| FR-206 | M6 暗網外洩憑證：整合 h8mail + HIBP API 查詢 domain 相關 Email 外洩記錄 | Nice to Have | M2 | 輸出 module_M6.json，含外洩帳號清單與來源 |
| FR-207 | M7 可疑偽冒網域：使用 dnstwist 生成 typosquat 變體，dnsx 驗證已解析域名 | Nice to Have | M2 | 輸出 module_M7.json，含已解析的偽冒域名清單 |

### 3.3 評分與報告模組（FR-300）

| ID | 需求描述 | 優先級 | 對應 ROADMAP | 驗收標準 |
|----|----------|--------|--------------|----------|
| FR-301 | 系統應實作七維度加權評分演算法，輸出 0-100 分及 A/B/C/D 等級 | Must Have | M3 | 輸入 findings.json → 輸出 score.json，分數與等級正確 |
| FR-302 | 系統應產出繁體中文 HTML 報告，含七大模組分頁與分數儀表板 | Must Have | M3 | HTML 報告可在瀏覽器正常顯示，繁中無亂碼 |
| FR-303 | 系統應支援將 HTML 報告轉為 PDF，使用 Noto Sans TC 中文字型 | Must Have | M3 | PDF 報告繁中正常顯示，無亂碼 |
| FR-304 | 系統應支援 JSON 原始資料與 CSV 匯出（資產清單 / CVE 清單） | Should Have | M3 | CSV 檔案可用 Excel 正確開啟 |

### 3.4 自動化與通知模組（FR-400）

| ID | 需求描述 | 優先級 | 對應 ROADMAP | 驗收標準 |
|----|----------|--------|--------------|----------|
| FR-402 | 系統應支援掃描結果差異比對，偵測新增/消失的風險項目 | Should Have | M4 | 比對兩次結果可正確輸出差異清單 |
| FR-403 | 系統應支援 Slack / Email / LINE Notify 通知 | Nice to Have | M4 | Critical/High 告警成功送達至少一個通知管道 |

> **優先級定義：**
> - **Must Have**：MVP 必須實作，否則無法作為 EASM 工具使用
> - **Should Have**：重要功能，應在初版完成
> - **Nice to Have**：有餘力時實作，可延至後續版本

---

## 4. 非功能需求（Non-Functional Requirements）

| 類別 | 需求 | 目標值 | 驗證方式 |
|------|------|--------|----------|
| **效能** | 單域名完整掃描時間 | < 30 分鐘 | 計時測試（中型目標約 50 子網域） |
| **效能** | 評分計算時間 | < 5 秒 | 計時測試 |
| **效能** | 報告產出時間（HTML + PDF） | < 60 秒 | 計時測試 |
| **儲存** | 單次掃描結果 JSON 大小 | < 100 MB | 檔案大小檢查 |
| **相容性** | 執行環境 | Linux（Docker） | Docker 環境測試 |
| **相容性** | Python 版本 | 3.10+ | CI 多版本測試 |
| **相容性** | 報告瀏覽器支援 | Chrome / Firefox / Edge 最新版 | 人工驗證 |
| **可維護性** | 測試覆蓋率 | > 80%（核心模組 > 90%） | `make coverage` |
| **可維護性** | 模組獨立性 | 每個安全模組可獨立執行與測試 | `make test-filter FILTER=module_name` |
| **安全性** | 不儲存目標敏感資料於日誌中 | 日誌無密碼/API Key | 日誌審查 |
| **安全性** | subprocess 輸入消毒 | 防止命令注入 | 安全測試 |
| **可擴充性** | 新增安全模組 | 實作 base class 即可 | 開發者文件驗證 |
| **國際化** | 報告語言 | 繁體中文（zh-TW） | 人工驗證 |

---

## 5. 使用者故事（User Stories）

### 5.1 資安分析師（Security Analyst）

---

**US-101: 子網域探勘**

- **As a** 資安分析師
- **I want** 輸入目標 domain 後自動探勘所有子網域與 HTTP 服務
- **So that** 我可以了解目標的完整外部攻擊面

**Acceptance Criteria:**

- [ ] 輸入 `cypulse scan example.com` 後自動探勘子網域
- [ ] 輸出包含子網域、IP、開放 Port、HTTP 服務資訊
- [ ] 結果以 JSON 格式儲存
- [ ] 流程全自動，無需手動介入

**Maps to:** FR-101, FR-102, FR-103, FR-104, FR-105 | Task: M1

---

**US-201: 資安曝險評級**

- **As a** 資安分析師
- **I want** 對目標 domain 取得一個量化的資安曝險評分
- **So that** 我可以快速了解目標的整體資安狀態並與其他目標比較

**Acceptance Criteria:**

- [ ] 七大模組全部執行完畢後產出總評分（0-100）
- [ ] 評分包含 A/B/C/D 等級與各維度分數
- [ ] 評分邏輯透明，可解釋每個扣分項目

**Maps to:** FR-201~FR-207, FR-301 | Task: M2, M3

---

**US-301: 資安報告產出**

- **As a** 資安分析師
- **I want** 取得繁體中文的 HTML 和 PDF 格式資安報告
- **So that** 我可以直接提供給管理層或客戶檢閱

**Acceptance Criteria:**

- [ ] HTML 報告包含七大模組分頁、分數儀表板
- [ ] PDF 報告繁中字型正常顯示
- [ ] 報告包含風險項目明細與改善建議
- [ ] 支援 CSV 匯出供進一步分析

**Maps to:** FR-302, FR-303, FR-304 | Task: M3

---

### 5.2 IT 管理員（IT Administrator）

---

**US-401: 掃描差異比對與通知**

- **As a** IT 管理員
- **I want** 在每次掃描後自動比對差異，並在發現新風險時收到通知
- **So that** 我可以即時掌握公司外部攻擊面的變化

**Acceptance Criteria:**

- [ ] 掃描結果差異比對可偵測新增風險
- [ ] Critical/High 風險透過 Slack 或 Email 即時通知
- [ ] 歷史結果依日期歸檔保存

**Maps to:** FR-402, FR-403 | Task: M4

---

### 5.3 開源社群貢獻者（Community Contributor）

---

**US-501: 模組擴充**

- **As a** 開源社群貢獻者
- **I want** 可以簡單地新增自訂安全分析模組
- **So that** 我可以為 CyPulse 貢獻新的掃描能力

**Acceptance Criteria:**

- [ ] 有清楚的模組開發文件與 base class 定義
- [ ] 新模組只需實作標準介面即可接入評分系統
- [ ] Docker 環境可一鍵啟動開發

**Maps to:** NFR（可擴充性）| Task: M4-T304

---

## 6. 使用場景（Use Cases）

### UC-101: 完整域名掃描與報告產出

**參與者：** 資安分析師、CyPulse CLI

**前置條件：** CyPulse 已安裝（Docker 或本地環境），目標 domain 已確認為授權掃描範圍

**後置條件：** 產出完整的掃描結果（JSON）、評分（score.json）與報告（HTML/PDF）

#### 主要流程（Main Flow）

1. 使用者執行 `cypulse scan example.com`
2. 系統執行 Layer 1 資產探勘（subfinder → dnsx → naabu → httpx）
3. 系統輸出 assets.json
4. 系統依序執行七大安全分析模組（M1-M7），各產出 module_MN.json
5. 系統整合為 findings.json
6. 系統執行評分演算法，產出 score.json
7. 系統渲染 HTML 報告
8. 系統轉出 PDF 報告
9. 系統輸出掃描完成摘要（分數、等級、掃描時間）

#### 替代流程（Alternative Flow）

- **A1 — 指定模組掃描：** 使用者執行 `cypulse scan example.com --modules M1,M5`，僅執行指定模組
- **A2 — 僅產出報告：** 使用者執行 `cypulse report <scan_dir>`，以既有掃描結果產出報告

#### 異常流程（Exception Flow）

- **E1 — 工具未安裝：** 偵測到缺少必要 CLI 工具 → 輸出錯誤訊息與安裝指引
- **E2 — 目標無回應：** DNS 解析失敗 → 記錄錯誤，跳過該子網域繼續
- **E3 — API 額度耗盡：** h8mail / AbuseIPDB API 返回 429 → 記錄警告，該模組標記為「部分結果」

---

### UC-201: 差異比對與告警

**參與者：** IT 管理員、CyPulse CLI

**前置條件：** 至少有兩次掃描結果

**後置條件：** 產出差異報告，新 Critical/High 項目觸發通知

#### 主要流程

1. 使用者執行 `cypulse scan` 或 `cypulse diff`
2. 掃描完成後，系統載入上次掃描結果
3. 系統比對兩次結果，產出差異清單
4. 若發現新 Critical/High 風險 → 發送通知
5. 若分數下降 > 10 分 → 發送告警
6. 差異報告歸檔

---

## 7. 資料模型概覽（Data Model）

> CyPulse 使用 JSON 檔案儲存，無關聯式資料庫。

### 7.1 核心資料結構

| 資料物件 | 說明 | 檔案路徑 | 格式 |
|----------|------|----------|------|
| `ScanResult` | 完整掃描結果 | `data/<domain>/<timestamp>/scan_result.json` | JSON |
| `Assets` | 資產清單 | `data/<domain>/<timestamp>/assets.json` | JSON |
| `ModuleResult` | 單一模組分析結果 | `data/<domain>/<timestamp>/module_M<N>.json` | JSON |
| `Findings` | 七大模組整合結果 | `data/<domain>/<timestamp>/findings.json` | JSON |
| `Score` | 評分結果 | `data/<domain>/<timestamp>/score.json` | JSON |
| `DiffReport` | 差異比對結果 | `data/<domain>/<timestamp>/diff.json` | JSON |

### 7.2 ScanResult JSON Schema（簡化）

```json
{
  "domain": "example.com",
  "scan_id": "uuid",
  "timestamp": "2026-03-12T02:00:00Z",
  "duration_seconds": 1200,
  "assets_count": 42,
  "score": {
    "total": 78,
    "grade": "C",
    "dimensions": {
      "M1_web_security": 18,
      "M2_ip_reputation": 15,
      "M3_network_security": 12,
      "M4_dns_security": 10,
      "M5_email_security": 8,
      "M6_darkweb_credentials": 10,
      "M7_fake_domains": 5
    }
  },
  "findings_summary": {
    "critical": 2,
    "high": 5,
    "medium": 12,
    "low": 8,
    "info": 20
  }
}
```

### 7.3 檔案儲存結構

```
data/
├── example.com/
│   ├── 2026-03-12T020000/
│   │   ├── assets.json
│   │   ├── module_M1.json
│   │   ├── module_M2.json
│   │   ├── ...
│   │   ├── module_M7.json
│   │   ├── findings.json
│   │   ├── score.json
│   │   ├── report.html
│   │   └── report.pdf
│   └── 2026-03-19T020000/
│       ├── ...
│       └── diff.json
└── another-domain.com/
    └── ...
```

---

## 8. 介面規格（Interface Spec）

> CyPulse 為 CLI 工具，無 Web 介面。

### 8.1 CLI 指令清單

| 指令 | 說明 | 範例 |
|------|------|------|
| `cypulse scan <domain>` | 執行完整掃描（探勘 + 分析 + 評分 + 報告） | `cypulse scan example.com` |
| `cypulse scan <domain> --modules M1,M5` | 僅執行指定模組 | `cypulse scan example.com --modules M1,M5` |
| `cypulse scan <domain> --output json` | 指定輸出格式 | `cypulse scan example.com --output json` |
| `cypulse report <scan_dir>` | 以既有掃描結果產出報告 | `cypulse report data/example.com/2026-03-12T020000` |
| `cypulse report <scan_dir> --format pdf` | 指定報告格式 | `cypulse report <dir> --format pdf` |
| `cypulse diff <dir1> <dir2>` | 比較兩次掃描結果 | `cypulse diff <old_dir> <new_dir>` |

### 8.2 CLI 輸出範例

```
$ cypulse scan example.com

🔍 CyPulse EASM Scanner v0.1.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Target: example.com

[1/4] 資產探勘...
  ✓ subfinder: 找到 35 個子網域
  ✓ dnsx: 28 個存活
  ✓ naabu: 42 個開放 Port
  ✓ httpx: 25 個 HTTP 服務

[2/4] 安全分析...
  ✓ M1 網站服務安全: 18/25
  ✓ M2 IP 信譽:      15/15
  ✓ M3 網路服務安全: 12/20
  ✓ M4 DNS 安全:     10/15
  ✓ M5 郵件安全:      8/10
  ✓ M6 暗網憑證:     10/10
  ✓ M7 偽冒域名:      5/5

[3/4] 評分計算...
  總分: 78/100 → 等級: C

[4/4] 報告輸出...
  ✓ HTML: data/example.com/2026-03-12T020000/report.html
  ✓ PDF:  data/example.com/2026-03-12T020000/report.pdf

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
掃描完成 | 耗時: 18m 32s | 等級: C (78/100)
```

---

## 9. 限制與假設（Constraints & Assumptions）

### 9.1 技術限制

- **語言**：Python 3.10+，Shell（Bash）
- **外部工具**：ProjectDiscovery CLI tools（Go binary），需預先安裝
- **容器**：Docker 20.10+，docker-compose v2
- **字型**：PDF 報告需安裝 Noto Sans TC

### 9.2 業務限制

- 預算：$0（僅使用免費工具與免費 API 額度）
- 開發人力：單人開發
- 完整建置週期：4 個月（16 週）
- 法律合規：僅掃描自有或明確授權的域名

### 9.3 假設

- 假設使用者具備基本 Linux 與 Docker 操作能力
- 假設目標 domain 已取得明確掃描授權
- 假設 ProjectDiscovery 工具持續維護並可從 GitHub 下載
- 假設 AbuseIPDB / HIBP 免費 API 額度足夠單域名掃描
- 假設掃描目標為中小型組織（子網域 < 500 個）

### 9.4 依賴項目

| 外部依賴 | 用途 | 備用方案 |
|----------|------|----------|
| subfinder / httpx / nuclei / dnsx / naabu | 資產探勘 + 漏洞掃描 | 無（核心依賴） |
| checkdmarc | 郵件安全分析 | 手動 DNS 查詢 |
| dnstwist | 偽冒域名偵測 | 手動排列組合 |
| h8mail | 暗網憑證搜尋 | HIBP 網頁版手動查詢 |
| AbuseIPDB API | IP 信譽查詢 | Spamhaus DROP list（離線） |
| weasyprint | PDF 產出 | 瀏覽器列印 HTML |
| Jinja2 | HTML 模板渲染 | 無（核心依賴） |

---

## 10. 追溯矩陣（Traceability Matrix）

| FR ID | 描述 | US ID | ROADMAP Task |
|-------|------|-------|--------------|
| FR-101 | 子網域被動列舉 | US-101 | T002, T003 |
| FR-102 | DNS 解析驗證 | US-101 | T004 |
| FR-103 | HTTP 服務探勘 | US-101 | T005 |
| FR-104 | Port 掃描 | US-101 | T006 |
| FR-105 | 一鍵探勘流水線 | US-101 | T007 |
| FR-201 | M1 網站服務安全 | US-201 | T101 |
| FR-202 | M2 IP 信譽 | US-201 | T102 |
| FR-203 | M3 網路服務安全 | US-201 | T103 |
| FR-204 | M4 DNS 安全 | US-201 | T104 |
| FR-205 | M5 郵件安全 | US-201 | T105 |
| FR-206 | M6 暗網憑證 | US-201 | T106 |
| FR-207 | M7 偽冒域名 | US-201 | T107 |
| FR-301 | 評分演算法 | US-201 | T201 |
| FR-302 | HTML 報告 | US-301 | T203 |
| FR-303 | PDF 報告 | US-301 | T204 |
| FR-304 | CSV 匯出 | US-301 | T205 |
| FR-402 | 差異比對 | US-401 | T302 |
| FR-403 | 通知整合 | US-401 | T303 |

---

## 附錄

### A. 評分權重與扣分邏輯

| 模組 | 權重 | 滿分 | 扣分邏輯 |
|------|------|------|----------|
| M1 網站服務安全 | 25% | 25 | Critical CVE -15 / 缺少 HSTS -5 / Mixed Content -3 |
| M2 IP 信譽 | 15% | 15 | 黑名單命中 -10 / 灰名單 -5 |
| M3 網路服務安全 | 20% | 20 | 高危 Port 開放 -10 / CVE 每個 -5 / 未加密服務 -5 |
| M4 DNS 安全 | 15% | 15 | Zone Transfer -10 / 無 DNSSEC -5 |
| M5 郵件安全 | 10% | 10 | 無 DMARC -6 / 無 SPF -4 / 無 DKIM -2 |
| M6 暗網憑證 | 10% | 10 | 每組外洩憑證 -3（上限 -10） |
| M7 偽冒域名 | 5% | 5 | 已解析偽冒域名每個 -1（上限 -5） |

### B. 評級對照表

| 等級 | 分數範圍 | 說明 |
|------|----------|------|
| A | 90–100 分 | 資安防護良好 |
| B | 80–89 分 | 資安防護尚可，有改善空間 |
| C | 70–79 分 | 存在明顯風險，建議儘速改善 |
| D | < 70 分 | 高風險，需立即處理 |

### C. 變更歷史

| 版本 | 日期 | 變更摘要 | 作者 |
|------|------|----------|------|
| v0.1.0 | 2026-03-12 | 初版建立 | CyPulse 開發團隊 |

### D. 相關文件

- [`SDS.md`](./SDS.md) — 軟體設計規格書
- [`DEPLOY_SPEC.md`](./DEPLOY_SPEC.md) — 部署規格書
- [`docs/adr/`](./adr/) — 架構決策記錄
- [`ROADMAP.yaml`](../ROADMAP.yaml) — 專案路線圖
