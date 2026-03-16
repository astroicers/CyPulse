# ADR-004: 評分去重、等級線性化與補救建議設計決策

| 欄位 | 內容 |
|------|------|
| **狀態** | Accepted |
| **日期** | 2026-03-16 |
| **決策者** | CyPulse 開發團隊 |
| **影響範圍** | `cypulse/analysis/`, `cypulse/scoring/weights.py`, `cypulse/remediation/`, `cypulse/discovery/pipeline.py`, `cypulse/utils/subprocess.py` |

---

## 背景

透過系統架構師、資安顧問、DevOps 工程師三個視角對 CyPulse 進行全面審查，識別出四類問題：

1. **評分膨脹**：M2（IP 信譽）、M3（網路服務）、M6（暗網憑證）均存在多來源重複計分，導致評分虛高 10-20%
2. **等級不對稱**：原 GRADES 設計中 D 等級範圍（0-69）佔 70%，B-C 邊界（80/70）不合理
3. **報告無可行動建議**：findings 僅列出問題，無對應修補步驟，報告對工程師實用性低
4. **效能與穩定性**：Discovery pipeline 單工具失敗即中止；subprocess backoff 無上限

---

## 決策

### 1. 多來源 findings 去重策略

**M2 IP 信譽**：每個 IP 以 `{ip}:{source_name}` 為去重 key，同一 IP 的相同來源只計最高衝擊的 finding。

**M3 網路服務 CVE**：nmap 輸出解析時以 `seen_cves: set[str]` 追蹤已出現的 CVE ID，同一 CVE 只產生一筆 finding。

**M6 暗網憑證**：HIBP 回傳的 breach 以 `breach_name` 去重，防止同名 breach 因大小寫差異被重複計分。

### 2. GRADES 等級閾值線性化

| 等級 | 新閾值 | 舊閾值 | 改動原因 |
|------|--------|--------|---------|
| A | 90-100 | 90-100 | 不變 |
| B | 75-89 | 80-89 | B 下限從 80 降至 75，擴大良好區間 |
| C | 60-74 | 70-79 | C 範圍從 10 分擴至 15 分，更精細 |
| D | 0-59 | 0-69 | 危險等級縮小，減少誤判 |

等級邊界間距由 10 調整為 15，D 等級從 70 分縮小為 60 分，避免中等風險被歸入危險等級。

### 3. Remediation Playbook 模組引入

新增 `cypulse/remediation/playbooks.py`，提供結構化補救建議。每個 playbook 包含：
- `priority`（P1/P2/P3）
- `target_team`（負責團隊）
- `timeline`（建議時限）
- `effort`（工作量估計）
- `steps`（逐步操作指引，含指令）
- `success_criteria`（驗收標準）

初始版本涵蓋 5 個高優先 findings：No SPF Record、No DMARC Record、Missing DNSSEC、Weak TLS Version、Zone Transfer Allowed。

報告 HTML 模板透過 `remediation_map` 為每個已知 finding 顯示可折疊補救建議區塊（`<details>`）。

### 4. Discovery pipeline 容錯策略

將 subfinder + amass 的並行執行從 `.result()` 改為 `as_completed` 模式：
- 任一工具失敗時記錄 WARNING 但繼續執行
- 僅使用成功工具的結果
- 整體 pipeline 不因單一工具失敗而中止

### 5. subprocess retry backoff 上限

`run_cmd()` 新增 `max_backoff: float = 60.0` 參數，backoff 計算改為 `min(retry_delay * (2 ** attempt), max_backoff)`，防止高 `retry_delay` + 多次重試導致等待時間過長。

---

## 替代方案

| 方案 | 捨棄原因 |
|------|---------|
| **跨來源去重（取最高 impact）** | M2/M3/M6 的多來源資料反映不同面向風險，不應互相替代 |
| **等級閾值不調整** | D 等級過大，中等風險企業容易被誤判為危險 |
| **固定 playbook 格式為 Markdown** | 需要在模板中動態渲染，dict 結構更靈活 |
| **pipeline 失敗即中止** | 工具未安裝或網路問題不應阻礙其他工具的掃描結果 |

---

## 影響

- `cypulse/analysis/ip_reputation.py`：`ip_candidates` dict 去重邏輯
- `cypulse/analysis/network.py`：`seen_cves` set 去重
- `cypulse/analysis/darkweb.py`：`seen_breach_names` set 去重
- `cypulse/scoring/weights.py`：GRADES 閾值更新
- `cypulse/remediation/playbooks.py`：新模組，5 個 playbook
- `cypulse/report/generator.py`：注入 `remediation_map`
- `cypulse/report/templates/report.html`：補救建議 `<details>` 區塊
- `cypulse/discovery/pipeline.py`：`as_completed` 容錯
- `cypulse/utils/subprocess.py`：`max_backoff` 參數

---

## 技術債

- Playbook 目前只有 5 個，後續應補充 M1/M3/M4 常見 findings 的 playbook
- GRADES 等級閾值目前仍為固定常數，未來可依產業別動態調整（見 ADR-002 技術債）
- `as_completed` 的 `timeout=180` 為硬編碼，應改為從 config 讀取
