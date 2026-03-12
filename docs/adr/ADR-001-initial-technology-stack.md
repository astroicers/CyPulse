# [ADR-001]: 初始技術棧選型

| 欄位 | 內容 |
|------|------|
| **狀態** | `Accepted` |
| **日期** | 2026-03-12 |
| **決策者** | CyPulse 開發團隊 |

---

## 背景（Context）

CyPulse 目標是以 100% 開源工具，建立完整的 EASM 資安曝險評級能力。專案需要在 4 個月、$0 工具授權預算的條件下，建立涵蓋七大資安面向的自動化掃描、評分與報告產出流水線。

核心需求：
- 子網域探勘與資產盤點（被動列舉為主）
- 七大安全模組（網站安全、IP 信譽、網路服務、DNS、郵件、暗網憑證、偽冒域名）
- 量化評分演算法（七維度加權，輸出 A/B/C/D 等級）
- 繁體中文 HTML / PDF 報告輸出
- Docker 容器化一鍵部署
- Cron 排程自動掃描與差異告警

技術棧選擇需考量：開發速度、安全工具生態整合度、報告產出能力、社群可維護性。

---

## 評估選項（Options Considered）

### 選項 A：Python + ProjectDiscovery CLI Tools + Docker

- **優點**：
  - ProjectDiscovery 生態系（subfinder / httpx / nuclei / dnsx / naabu）為業界標準
  - checkdmarc、dnstwist、h8mail 均為 Python 原生套件，直接 import 使用
  - Jinja2 + weasyprint 完美解決 HTML/PDF 繁中報告需求
  - Python 開發速度快，4 個月時程內可完成全部模組
  - Docker 封裝簡單，支援開源社群一鍵部署
  - 豐富的資安相關 Python 套件生態

- **缺點**：
  - PD 工具為 Go 編譯的 CLI，需透過 subprocess 呼叫，非原生整合
  - Python GIL 限制真正的並行掃描效能
  - subprocess 依賴增加 Docker Image 體積

- **風險**：低 — 技術棧成熟，社群活躍

### 選項 B：Go + 自建掃描引擎

- **優點**：
  - PD 工具本身以 Go 開發，可直接引用為 library
  - 編譯後單一 binary，部署極簡
  - 真正的並行掃描，效能優異

- **缺點**：
  - Go 的資安工具 library 相對較少（checkdmarc、dnstwist 無 Go 版本）
  - HTML/PDF 報告產出在 Go 生態中不成熟
  - 開發速度慢，4 個月時程風險高
  - 社群貢獻門檻較高

- **風險**：中 — 開發時程可能不足

### 選項 C：Node.js + Puppeteer

- **優點**：
  - 非同步 I/O 適合網路密集操作
  - Puppeteer 可做網站截圖與深度分析

- **缺點**：
  - 資安掃描工具生態極度匱乏
  - 無法整合 checkdmarc / dnstwist / h8mail
  - 記憶體消耗大，不適合長時間掃描
  - PDF 產出依賴 Chrome headless，過重

- **風險**：高 — 不適合此領域

---

## 決策（Decision）

> 我們選擇 **選項 A：Python + ProjectDiscovery CLI Tools + Docker**。

理由：
1. **生態整合度最高**：七大模組中有 3 個（checkdmarc、dnstwist、h8mail）為 Python 原生套件，其餘 4 個透過 PD CLI 呼叫即可，整合成本最低
2. **報告能力最強**：Jinja2 + weasyprint 原生支援繁中 HTML/PDF 報告，無需額外處理
3. **開發速度最快**：Python 快速原型能力與 4 個月時程高度匹配
4. **社群友善**：Python 為資安社群最常用語言，開源後易於接收社群貢獻
5. **Docker 封裝成熟**：python:3.11-slim + PD binary 下載，Image 體積可控

---

## 後果（Consequences）

**正面影響：**
- 開發速度快，可在 4 個月內完成全部 7 模組 + 評分 + 報告 + 自動化
- 社群貢獻門檻低，有利於開源生態發展
- 豐富的 Python 資安工具可用於未來擴充

**負面影響 / 技術債：**
- PD 工具透過 subprocess 呼叫，需處理進程管理、timeout、錯誤解析
- JSON 檔案儲存在大量歷史掃描時可能遇到 I/O 瓶頸（已知限制，Phase 1 不處理）
- Docker Image 因包含 Go binary + Python 環境，體積較大（預估 > 500MB）

**後續追蹤：**
- [ ] 評估 asyncio + subprocess 並行掃描效能
- [ ] 若社群需求增加，考慮加入 SQLite 作為可選儲存後端
- [ ] 定期更新 PD 工具 binary 版本

---

## 成功指標（Success Metrics）

| 指標 | 目標值 | 驗證方式 | 檢查時間 |
|------|--------|----------|----------|
| 工具整合率 | 7/7 模組正常運作 | `make test` 全通過 | M2 完成時 |
| 單域名完整掃描時間 | < 30 分鐘 | 計時測試 | M3 完成時 |
| HTML 報告正確性 | 七大模組分頁完整 | 人工驗證 | M3 完成時 |
| PDF 繁中顯示 | 無亂碼 | 人工驗證 | M3 完成時 |
| Docker 一鍵啟動 | `docker-compose up` 成功 | 自動化測試 | M4 完成時 |

> 若掃描效能無法在 30 分鐘內完成，應重新評估是否需要 Go 重寫核心掃描模組。

---

## 關聯（Relations）

- 取代：（無）
- 被取代：（無）
- 參考：CyPulse_Roadmap.docx
