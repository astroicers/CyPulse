# 軟體設計規格書 (Software Design Specification)

| 欄位 | 內容 |
|------|------|
| **專案名稱** | CyPulse — 開源 EASM 資安曝險評級平台 |
| **版本** | v0.1.0 |
| **最後更新** | 2026-03-12 |
| **狀態** | Draft |
| **依據 SRS** | SRS v0.1.0 |
| **作者** | CyPulse 開發團隊 |
| **審閱者** | — |

---

## 1. 系統架構概覽

### 1.1 架構風格

本系統採用 **三層管線架構（Three-Layer Pipeline Architecture）**，原因：

- 資安掃描天然符合「探勘 → 分析 → 輸出」的管線模式
- 各層之間以 JSON 檔案解耦，支援模組獨立執行與測試
- 管線式設計使新模組擴充只需實作標準介面
- 架構簡單，單人開發 4 個月可完成（ADR-001 決策）

**架構原則：**

1. 層間以 JSON 檔案傳遞資料，各層可獨立執行
2. 每個安全分析模組實作共同 Base Class，可獨立測試
3. 外部 CLI 工具透過 subprocess wrapper 呼叫，封裝錯誤處理與 timeout

### 1.2 三層管線架構

```
┌──────────────────────────────────────────────────────┐
│            CLI 入口（cypulse/cli.py）                 │
│   指令解析、流程編排、進度顯示                         │
├──────────────────────────────────────────────────────┤
│     Layer 1：資產探勘（cypulse/discovery/）            │
│   subfinder → amass → dnsx → naabu → httpx           │
│   輸出：assets.json                                   │
├──────────────────────────────────────────────────────┤
│     Layer 2：風險分析（cypulse/analysis/）             │
│   M1~M7 七大安全模組（可並行）                        │
│   輸出：module_M1.json ~ module_M7.json → findings.json│
├──────────────────────────────────────────────────────┤
│     Layer 3：評分 & 報告（cypulse/scoring/ + report/） │
│   七維度加權評分 → HTML/PDF/CSV 報告                  │
│   輸出：score.json + report.html + report.pdf         │
└──────────────────────────────────────────────────────┘
```

### 1.3 部署架構

```
[使用者本機 / VPS]
    │
    ▼
[Docker Container: cypulse]
    │
    ├── Python 3.11 Runtime
    ├── PD Tools (Go binaries): subfinder, httpx, nuclei, dnsx, naabu
    ├── System Tools: nmap, testssl.sh, dnsrecon
    ├── Python Packages: checkdmarc, dnstwist, h8mail, jinja2, weasyprint
    └── Noto Sans TC Font
    │
    └── Volume Mount: ./data/ (掃描結果持久化)
```

**基礎設施選擇：**

| 元件 | 選擇 | 理由 |
|------|------|------|
| 執行環境 | Docker（python:3.11-slim） | 封裝所有依賴，一鍵部署 |
| 儲存 | JSON 檔案（host volume） | 無資料庫，簡單直接 |
| 通知 | HTTP Webhook + SMTP | 無需 MQ |

---

## 2. 模組設計

### 2.1 模組清單

| 模組名稱 | 職責 | 主要介面 | 內部依賴 | 外部依賴 |
|----------|------|----------|----------|----------|
| `cli` | CLI 入口、參數解析、流程編排 | `main()` | 全部模組 | argparse |
| `discovery` | 資產探勘（5 個子模組） | `run_discovery(domain) → Assets` | — | subfinder, amass, dnsx, httpx, naabu |
| `analysis` | 七大安全分析（7 個子模組） | `AnalysisModule.run(assets) → ModuleResult` | — | nuclei, nmap, checkdmarc, etc. |
| `scoring` | 評分引擎 | `calculate_score(findings) → Score` | — | — |
| `report` | 報告產出 | `generate_report(score, findings) → files` | — | Jinja2, weasyprint |
| `automation` | diff、通知 | `diff()`, `notify()` | scoring, report | requests, smtplib |
| `models` | 資料模型定義 | dataclass definitions | — | — |
| `utils` | 通用工具（subprocess、logging） | `run_cmd()`, `sanitize_domain()` | — | — |

### 2.2 各模組詳細設計

#### CLI 模組（cypulse/cli.py）

**職責：** 指令解析、流程編排、進度顯示

**核心介面：**

```python
def main():
    """CLI 入口點（argparse）"""

def cmd_scan(domain: str, modules: list[str] | None, output: str):
    """執行完整掃描流程"""

def cmd_report(scan_dir: str, format: str):
    """以既有結果產出報告"""

def cmd_diff(dir1: str, dir2: str):
    """比較兩次掃描結果"""
```

---

#### Discovery 模組（cypulse/discovery/）

**職責：** 封裝 5 個資產探勘工具，輸出統一格式的 assets.json

**核心介面：**

```python
class DiscoveryTool(ABC):
    """資產探勘工具基底類別"""

    @abstractmethod
    def run(self, domain: str, config: dict) -> list[dict]:
        """執行探勘，回傳結果列表"""

    @abstractmethod
    def name(self) -> str:
        """工具名稱"""

class SubfinderTool(DiscoveryTool): ...
class AmassTool(DiscoveryTool): ...
class DnsxTool(DiscoveryTool): ...
class HttpxTool(DiscoveryTool): ...
class NaabuTool(DiscoveryTool): ...

def run_discovery(domain: str, config: dict) -> Assets:
    """執行完整資產探勘流水線"""
```

---

#### Analysis 模組（cypulse/analysis/）

**職責：** 七大安全分析模組，各自封裝不同工具，輸出標準化 ModuleResult

**核心介面：**

```python
class AnalysisModule(ABC):
    """安全分析模組基底類別"""

    @abstractmethod
    def module_id(self) -> str:
        """模組代號（M1~M7）"""

    @abstractmethod
    def module_name(self) -> str:
        """模組名稱"""

    @abstractmethod
    def weight(self) -> float:
        """評分權重（0.0~1.0）"""

    @abstractmethod
    def max_score(self) -> int:
        """該模組滿分"""

    @abstractmethod
    def run(self, assets: Assets) -> ModuleResult:
        """執行分析，回傳 ModuleResult"""

class WebSecurityModule(AnalysisModule):     # M1, weight=0.25, max=25
class IPReputationModule(AnalysisModule):    # M2, weight=0.15, max=15
class NetworkSecurityModule(AnalysisModule): # M3, weight=0.20, max=20
class DNSSecurityModule(AnalysisModule):     # M4, weight=0.15, max=15
class EmailSecurityModule(AnalysisModule):   # M5, weight=0.10, max=10
class DarkWebModule(AnalysisModule):         # M6, weight=0.10, max=10
class FakeDomainModule(AnalysisModule):      # M7, weight=0.05, max=5
```

**決策說明：** 使用 ABC（Abstract Base Class）確保所有模組實作統一介面，新增模組只需繼承 `AnalysisModule` 並實作 4 個方法。

---

#### Scoring 模組（cypulse/scoring/）

**職責：** 接收七大模組結果，計算加權總分與等級

**核心介面：**

```python
class ScoringEngine:
    """七維度加權評分引擎"""

    def calculate(self, findings: Findings) -> Score:
        """
        計算總分與等級
        - 各模組分數加總（已依權重分配滿分）
        - 總分 0-100
        - 等級：A(90-100) B(80-89) C(70-79) D(<70)
        """

    def explain(self, score: Score) -> list[ScoreExplanation]:
        """
        產出扣分明細（供報告使用）
        每個扣分項包含：模組、原因、扣分值
        """
```

**評分權重配置（cypulse/scoring/weights.py）：**

```python
WEIGHTS = {
    "M1": {"weight": 0.25, "max_score": 25},
    "M2": {"weight": 0.15, "max_score": 15},
    "M3": {"weight": 0.20, "max_score": 20},
    "M4": {"weight": 0.15, "max_score": 15},
    "M5": {"weight": 0.10, "max_score": 10},
    "M6": {"weight": 0.10, "max_score": 10},
    "M7": {"weight": 0.05, "max_score":  5},
}

GRADES = {
    "A": (90, 100),
    "B": (80, 89),
    "C": (70, 79),
    "D": (0, 69),
}
```

---

#### Report 模組（cypulse/report/）

**職責：** 將評分與分析結果渲染為 HTML/PDF/CSV 報告

**核心介面：**

```python
class ReportGenerator:
    """報告產出器"""

    def generate_html(self, score: Score, findings: Findings,
                      assets: Assets, output_dir: str) -> str:
        """產出 HTML 報告，回傳檔案路徑"""

    def generate_pdf(self, html_path: str, output_dir: str) -> str:
        """HTML → PDF（weasyprint），回傳檔案路徑"""

    def generate_csv(self, findings: Findings,
                     assets: Assets, output_dir: str) -> list[str]:
        """產出 CSV 匯出檔案，回傳檔案路徑列表"""
```

**HTML 模板結構（cypulse/report/templates/）：**

```
templates/
├── base.html           # 基底模板（header, footer, CSS）
├── report.html         # 主報告頁面（總覽 + 分數儀表板）
├── module_detail.html  # 單一模組詳細頁面
├── assets_table.html   # 資產清單表格
└── static/
    ├── style.css       # 報告樣式
    └── logo.svg        # CyPulse Logo
```

---

#### Automation 模組（cypulse/automation/）

**職責：** 差異比對、通知發送

**核心介面：**

```python
class DiffEngine:
    """掃描結果差異比對"""

    def compare(self, old_dir: str, new_dir: str) -> DiffReport:
        """比較兩次掃描結果，回傳差異"""

class Notifier(ABC):
    """通知發送基底類別"""

    @abstractmethod
    def send(self, message: str, severity: str) -> bool:
        """發送通知"""

class SlackNotifier(Notifier): ...
class EmailNotifier(Notifier): ...
class LineNotifier(Notifier): ...
```

---

### 2.3 Python 專案結構

```
cypulse/
├── __init__.py
├── cli.py                    # CLI 入口（argparse）
├── discovery/
│   ├── __init__.py
│   ├── base.py               # DiscoveryTool ABC
│   ├── subfinder.py
│   ├── amass.py
│   ├── dnsx.py
│   ├── httpx.py
│   ├── naabu.py
│   └── pipeline.py           # run_discovery() 流水線編排
├── analysis/
│   ├── __init__.py
│   ├── base.py               # AnalysisModule ABC
│   ├── web_security.py       # M1
│   ├── ip_reputation.py      # M2
│   ├── network.py            # M3
│   ├── dns_security.py       # M4
│   ├── email_security.py     # M5
│   ├── darkweb.py            # M6
│   └── fake_domain.py        # M7
├── scoring/
│   ├── __init__.py
│   ├── engine.py             # ScoringEngine
│   └── weights.py            # 權重配置
├── report/
│   ├── __init__.py
│   ├── generator.py          # ReportGenerator
│   └── templates/
│       ├── base.html
│       ├── report.html
│       ├── module_detail.html
│       └── static/
├── automation/
│   ├── __init__.py
│   ├── diff.py               # 差異比對
│   └── notifier.py           # Slack/Email/LINE
├── models/
│   ├── __init__.py
│   ├── assets.py             # Assets dataclass
│   ├── findings.py           # Findings, ModuleResult dataclass
│   └── score.py              # Score, ScoreExplanation dataclass
└── utils/
    ├── __init__.py
    ├── subprocess.py          # run_cmd() 封裝
    ├── sanitize.py            # domain 格式驗證
    └── logging.py             # structured logging

tests/
├── test_discovery/
├── test_analysis/
├── test_scoring/
├── test_report/
├── test_automation/
└── conftest.py               # pytest fixtures

config/
└── config.yaml.example       # API Key 等設定範本
```

---

## 3. 資料設計

> CyPulse 使用 JSON 檔案儲存，無關聯式資料庫。

### 3.1 核心資料模型

#### Assets（資產清單）

```python
@dataclass
class Asset:
    subdomain: str               # e.g., "www.example.com"
    ip: str | None               # e.g., "1.2.3.4"
    ports: list[int]             # e.g., [80, 443, 8080]
    http_status: int | None      # e.g., 200
    http_title: str | None       # e.g., "Example Corp"
    tls_version: str | None      # e.g., "TLSv1.3"
    security_headers: dict       # e.g., {"HSTS": true, "CSP": false}

@dataclass
class Assets:
    domain: str
    timestamp: str               # ISO 8601
    subdomains: list[Asset]
    total_subdomains: int
    total_live: int
    total_http: int
```

#### ModuleResult（模組分析結果）

```python
@dataclass
class Finding:
    severity: str                # critical / high / medium / low / info
    title: str                   # 發現項目標題
    description: str             # 描述
    evidence: str | None         # 證據（URL、IP、CVE 編號等）
    score_impact: int            # 扣分值

@dataclass
class ModuleResult:
    module_id: str               # M1 ~ M7
    module_name: str
    score: int                   # 該模組得分（滿分見 weights）
    max_score: int
    findings: list[Finding]
    raw_data: dict               # 原始工具輸出
    execution_time: float        # 執行秒數
    status: str                  # success / partial / error
```

#### Score（評分結果）

```python
@dataclass
class ScoreExplanation:
    module_id: str
    reason: str
    deduction: int               # 扣分值

@dataclass
class Score:
    total: int                   # 0-100
    grade: str                   # A / B / C / D
    dimensions: dict[str, int]   # {"M1": 18, "M2": 15, ...}
    explanations: list[ScoreExplanation]
    scan_duration: float         # 總掃描秒數
```

#### DiffReport（差異比對）

```python
@dataclass
class DiffItem:
    category: str                # new_finding / resolved / score_change
    severity: str | None
    description: str

@dataclass
class DiffReport:
    old_scan: str                # 舊掃描 timestamp
    new_scan: str                # 新掃描 timestamp
    score_change: int            # 分數變化（正=改善，負=惡化）
    new_findings: list[DiffItem]
    resolved_findings: list[DiffItem]
    alerts: list[str]            # 需要告警的項目
```

### 3.2 JSON 儲存格式

所有資料以 JSON 儲存於 `data/<domain>/<timestamp>/` 目錄：

```
data/example.com/2026-03-12T020000/
├── assets.json          # Assets
├── module_M1.json       # ModuleResult
├── module_M2.json
├── module_M3.json
├── module_M4.json
├── module_M5.json
├── module_M6.json
├── module_M7.json
├── findings.json        # 整合 M1~M7
├── score.json           # Score
├── report.html
├── report.pdf
└── diff.json            # DiffReport（若有前次結果）
```

---

## 4. CLI 介面合約

### 4.1 基本規範

- **入口點：** `cypulse`（setup.py console_scripts 或 `python -m cypulse`）
- **設定檔：** `config/config.yaml`（API Key 等）
- **輸出目錄：** `data/`（可透過 `CYPULSE_OUTPUT_DIR` 環境變數覆蓋）

### 4.2 指令規格

#### `cypulse scan <domain>`

```
用法: cypulse scan <domain> [選項]

引數:
  domain                目標域名（必填）

選項:
  --modules M1,M2,...   僅執行指定模組（預設全部）
  --output FORMAT       輸出格式：json|html|pdf|all（預設 all）
  --config PATH         設定檔路徑（預設 config/config.yaml）
  --timeout SECONDS     單一工具最長執行時間（預設 300）
  --rate-limit N        掃描速率限制（預設 50 req/s）
  -v, --verbose         詳細輸出
  -q, --quiet           靜默模式（僅輸出最終分數）
```

#### `cypulse report <scan_dir>`

```
用法: cypulse report <scan_dir> [選項]

引數:
  scan_dir              掃描結果目錄（必填）

選項:
  --format FORMAT       報告格式：html|pdf|csv|all（預設 all）
  --output-dir PATH     報告輸出目錄（預設同 scan_dir）
```

#### `cypulse diff <dir1> <dir2>`

```
用法: cypulse diff <dir1> <dir2> [選項]

引數:
  dir1                  舊掃描結果目錄
  dir2                  新掃描結果目錄

選項:
  --notify              觸發通知（依 config.yaml 設定）
```

### 4.3 Exit Codes

| Code | 說明 |
|------|------|
| 0 | 成功完成 |
| 1 | 一般錯誤 |
| 2 | 參數錯誤 |
| 3 | 工具未安裝 |
| 4 | 設定檔缺失 |
| 5 | 掃描部分失敗（部分模組出錯，結果可能不完整） |

---

## 5. 安全設計

### 5.1 subprocess 安全

所有外部 CLI 工具呼叫通過 `utils/subprocess.py` 封裝：

```python
def run_cmd(cmd: list[str], timeout: int = 300,
            input_data: str | None = None) -> CmdResult:
    """
    安全執行外部指令
    - cmd 以 list 傳入（非 shell=True），防止命令注入
    - timeout 控制最長執行時間
    - 不記錄包含敏感資料的 stdout/stderr
    """
```

### 5.2 輸入消毒

```python
def sanitize_domain(domain: str) -> str:
    """
    驗證並清理 domain 輸入
    - 僅允許 [a-zA-Z0-9.-]
    - 移除前後空白
    - 轉為小寫
    - 長度限制 253 字元
    - 不允許 IP 格式（除非明確指定）
    """
```

### 5.3 API Key 保護

- API Key 存放於 `config/config.yaml` 或 `.env`（加入 .gitignore）
- 環境變數優先於設定檔
- 日誌中以 `***` 遮蔽 API Key
- 提供 `config/config.yaml.example` 範本（不含實際 Key）

---

## 6. 效能設計

### 6.1 掃描效能

| 階段 | 策略 | 預期時間 |
|------|------|----------|
| 資產探勘 | subfinder + amass 並行 → dnsx → naabu + httpx 並行 | 5-8 分鐘 |
| 七大模組 | 初版序列執行，Phase 2 改為 multiprocessing 並行 | 10-20 分鐘 |
| 評分計算 | 純 Python 計算 | < 1 秒 |
| 報告產出 | Jinja2 + weasyprint | 10-30 秒 |

### 6.2 資源控制

- **subprocess timeout**：每個外部工具預設 300 秒 timeout
- **rate-limit**：nuclei 使用 `-rate-limit 50` 控制掃描速率
- **記憶體**：Docker 建議分配 4GB RAM
- **磁碟**：單次掃描結果約 10-50 MB

### 6.3 未來優化方向

- `asyncio` + `subprocess` 實現七大模組真正並行
- 增量掃描（僅掃描新增/變更的資產）
- 結果快取（相同 asset 在 TTL 內不重複掃描）

---

## 7. ADR 交叉引用

| ADR ID | 標題 | 影響的設計決策 |
|--------|------|----------------|
| ADR-001 | 初始技術棧選型（Python + PD + Docker） | 全部模組設計、部署架構 |

---

## 附錄

### A. 技術債追蹤

| 項目 | 說明 | 優先級 | 預計解決版本 |
|------|------|--------|--------------|
| 序列掃描 | 七大模組目前序列執行 | Medium | v0.2.0 |
| JSON 儲存 | 大量歷史掃描時 I/O 瓶頸 | Low | v0.3.0 |
| PD 版本管理 | 無自動更新 binary 機制 | Low | v0.2.0 |

### B. 變更歷史

| 版本 | 日期 | 變更摘要 | 作者 |
|------|------|----------|------|
| v0.1.0 | 2026-03-12 | 初版建立 | CyPulse 開發團隊 |

### C. 相關文件

- [`SRS.md`](./SRS.md) — 軟體需求規格書
- [`DEPLOY_SPEC.md`](./DEPLOY_SPEC.md) — 部署規格書
- [`architecture.md`](./architecture.md) — 系統架構文件
- [`docs/adr/`](./adr/) — 架構決策記錄
