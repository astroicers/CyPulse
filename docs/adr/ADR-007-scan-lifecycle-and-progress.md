# ADR-007: 掃描 Lifecycle 與進度顯示

| 欄位 | 內容 |
|------|------|
| **狀態** | Accepted |
| **日期** | 2026-04-18 |
| **決策者** | CyPulse 開發團隊 |
| **影響範圍** | `cypulse/cli.py`、`cypulse/utils/scan_lifecycle.py`（新）、`cypulse/analysis/runner.py`、`cypulse/discovery/pipeline.py`、`cypulse/analysis/{web_security,cloud_exposure}.py`、`cypulse/report/templates/report.html` |

---

## 背景

實測 ylh.gov.tw 掃描花 130 秒，期間使用者只看到 5 行 Phase 標題，多次反饋「以為卡住」。同時發現幾個穩定性缺口：

1. **無 wall-clock deadline**：若 nmap、subfinder 卡住，整個掃描永不結束（企業自動化必須有終止保證）
2. **Ctrl-C 無清理**：直接拋 KeyboardInterrupt → temp 檔（nuclei hosts file、s3scanner buckets file）殘留 `/tmp/`
3. **score.json 已含 confidence/source_coverage 但 HTML 未呈現**（Task H 寫入但 Task N 才補視覺化）

本 ADR 記錄四個關聯的設計決策。

---

## 決策

### 1. 進度顯示：phase-based progressbar + spinner

**選擇：** `click.progressbar` 包裹 Phase 1（5 sub-steps）與 Phase 2（N modules）；Phase 3/4/5 短時間用普通 `click.echo`。

**實作關鍵：** `runner.run_analysis()` 與 `pipeline.run_discovery()` 各加 `on_module_done` / `on_step_done` callback 參數（預設 None，向後相容）。CLI 在 callback 內呼叫 `bar.update(1, current_item=...)`。

**捨棄方案：**
- **rich.progress** — 多一個依賴，且報告本身用 jinja2 已有 UI 路線
- **顯示每個 subdomain 進度** — 太細碎，不如 phase 級資訊有用

### 2. Timeout 機制：signal.alarm（Unix-only）

**選擇：** `signal.SIGALRM + signal.alarm(N)`，CyPulse Docker base 為 `python:3.11-slim` (Linux)，Unix-only 可接受。

**捨棄方案：**
- **threading.Timer** — 跨平台但無法中斷主執行緒的 subprocess wait（需要每個 subprocess 都檢查 abort flag，侵入性高）
- **multiprocessing.Process + timeout** — 通訊成本高，且狀態還原複雜

**Exit code：** 124（GNU `timeout` 慣例）

### 3. Graceful shutdown：SIGINT 兩段式

**選擇：** 第一次 SIGINT → `ctx.abort` + `cleanup_temp_files`，讓主流程的 `try/except ScanAborted` 接手；第二次 SIGINT → `raise KeyboardInterrupt` 強制離開。

**理由：** 第一次 Ctrl-C 大多是「我等不及了」，給機會清理；第二次 Ctrl-C 是「立刻給我退出」，cleanup 卡住時必須能逃。

**Exit code：** 130（128 + SIGINT 信號編號 2）

### 4. ScanContext 抽象（中央 lifecycle 狀態）

**選擇：** 新增 `cypulse/utils/scan_lifecycle.py`，提供：
- `ScanContext` class：abort flag、abort reason、temp files registry、deadline 計算
- `ScanAborted` exception：供主流程 `try/except` 統一接手
- module-level `_active_context` + `set/get_active_scan_context()`：跨層模組（web_security、cloud_exposure）註冊 temp 檔到當前 scan
- `install_sigint_handler(ctx)`：兩段式 SIGINT handler

**捨棄方案：**
- **ContextVars** — 太現代，且 SIGINT handler 在主執行緒外無 contextvar
- **直接綁 signal 到 ScanContext class** — 不便於單元測試（無法不真的 raise 信號就驗證行為）

**設計關鍵：** ScanContext 本身**不綁 signal**。signal handler 由 `cli.py` 註冊並呼叫 `ctx.abort()` + `ctx.cleanup_temp_files()`，這樣 ScanContext 可獨立單元測試（見 `tests/test_utils/test_scan_lifecycle.py`）。

### 5. 信心分數視覺化（Task N）

`Score.confidence` 與 `Score.source_coverage`（ADR-006 引入）原本只寫入 `score.json`，HTML 報告未呈現。本次補：

- **score-card** 顯示「掃描信心：92%」徽章；< 0.8 改紅色 + 黃字提示重跑
- **dim-card** 在 coverage < 1.0 時加「來源覆蓋 X%」小字
- **新增「掃描覆蓋警示」區塊**（僅當有 failed sources 時顯示），列出每個模組的失效來源 ID 與錯誤原因

不動 `generator.py`：既有 context 已包含 `score` 與 `module.sources`，純模板層改動。

---

## 後果

### 優點
- **使用者體驗**：130 秒掃描期間有實時進度 + ETA，不再誤判卡住
- **企業自動化**：`--timeout` 提供 wall-clock 上限，cron 排程不會無限掛起
- **穩定性**：Ctrl-C 不再殘留 temp 檔；信心分數透明化讓使用者判斷是否重跑
- **可測試性**：ScanContext 抽象讓 lifecycle 邏輯可獨立 TDD（16 筆 unit + 7 筆 SIT）

### 取捨
- **Linux-only**：signal.alarm 不支援 Windows；CyPulse 既已是 Linux Docker，可接受
- **callback 散落**：CLI 與 runner/pipeline 之間多了 callback 契約，未來新增 phase 需手動註冊
- **HTML 模板複雜度**：jinja2 內 `selectattr("status", "equalto", "failed")` 雖不複雜但需熟悉 jinja2

### 不納入本決策
- 多 domain 並行掃描 → 下一輪 Phase 2
- Scan resume（中斷後從 checkpoint 繼續） → 下一輪 Phase 2
- weasyprint warning 抑制 → cosmetic，視需要再做

---

## 相關
- ADR-006：來源級韌性追蹤與信心分數（confidence 欄位定義）
- Task H commit `e270657`：confidence 寫入 score.json
- Task M-P commits（本 ADR 對應）：`8d1b440`（進度條）、`565c5c1`（HTML 視覺化）、`d227863`（timeout）、`822deb8`（Ctrl-C）
- SIT commit：`4b129b7`（端到端整合測試）
