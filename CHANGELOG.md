# Changelog

所有重要變更記錄在此，格式依循 [Keep a Changelog](https://keepachangelog.com/zh-TW/1.0.0/)。

---

## [0.5.0] - 2026-04-19

主軸：**後勤改善 + 安全加固 + DX**（見 [ADR-008](docs/adr/ADR-008-observability-and-secret-masking.md)）。

### Added

- **structlog `_mask_secrets` processor**：自動 mask log 內 `api_key|token|password|secret|webhook|authorization|bearer` 欄位的值
  - dict / list（cmd args）遞迴處理；長度 > 8 保留前 4 字 + `***`
  - Defense-in-depth：未來新增模組若不小心 log 到 secret 也會自動 mask
- **`cypulse/utils/diagnostics.py:format_error()`**：將常見 Exception 分類並回傳「修復建議」
  - 涵蓋 ImportError(dns)、subprocess.TimeoutExpired、requests.Timeout/ConnectionError、FileNotFoundError(tool)、DiffSchemaError、ScanAborted
  - CLI scan except 區塊使用，使用者看到的錯誤訊息直接含可行動指令
- **scan_id contextvar**：CLI scan 開頭 `bind_contextvars(scan_id=uuid12, domain=...)`，所有 log event 自動含這兩個 key
- **`Score.scan_id`** 新欄位（`default=None`），`score.json` 含此值供跨 log 追溯
- **`cypulse scan --export-logs PATH`**：scan 結束時將整段 log 匯出為 jsonl（每筆 event 含 scan_id），便於發 issue 附完整脈絡
- **`cypulse list-modules`**：印 M1–M8 + 名稱 + 權重 + 滿分表格 + 總計驗證
- **`cypulse scan --dry-run`**：預檢模式：domain 格式 ✓、列模組、檢查工具/API key 可用性，不執行 Phase 1-5
- **`DiffSchemaError`** + 新/舊 scan 區分處理：
  - 新 scan 缺必要鍵 → raise（代碼 bug 必須失敗）
  - 舊 scan 缺鍵 → 回傳含警示 alert 的空 DiffReport（cron 不被拖垮）

### Changed

- `cypulse/automation/diff.py:save_diff` 改用 `safe_write_json`（補 Task F 漏掉的第 6 個寫入點）
- `cypulse/cli.py scan` 新增 `except Exception` 區塊用 `format_error` 包裝錯誤
- `pyproject.toml` version 0.4.0 → 0.5.0

### Meta（測試覆蓋率提升）

- 既有 331 + 7 SIT → **356 unit + 7 SIT pass**（+25 unit）
- `cypulse/cli.py` coverage: **36% → 82%**（+46pp）
- Overall coverage: 84% → **89%**

### Fixed

- 修復 diff 載入舊版 scan 時靜默回 `{}` 導致所有 finding 被誤判為 resolved 的 bug
- 修復 `save_diff` 非 atomic 寫入可能在中斷時毀檔的 bug

---

## [0.4.0] - 2026-04-18

主軸：**實際掃描體驗的可用性 + 韌性強化**（見 [ADR-007](docs/adr/ADR-007-scan-lifecycle-and-progress.md)）。

### Added

- **CLI 進度條 + ETA**：`cypulse scan` 期間 Phase 1（5 sub-steps）與 Phase 2（N modules）
  以 `click.progressbar` 顯示即時進度與剩餘時間估計；每個 phase 結尾印實際耗時
- **HTML 報告呈現信心分數**：
  - score-card 加「掃描信心：92%」徽章（< 0.8 改紅色 + 重跑提示）
  - 八維度評分卡顯示「來源覆蓋 X%」（< 100% 時）
  - 新增「掃描覆蓋警示」區塊（僅當有 failed sources 時顯示，列出失效來源與錯誤原因）
- **掃描全局 timeout** `--timeout INTEGER`（預設 1800s）：
  超時 → 自動 cleanup temp 檔、abort scan、exit code 124（GNU timeout 慣例）
- **Ctrl-C graceful shutdown**：
  - 第一次 SIGINT → cleanup temp 檔 + abort + exit 130
  - 第二次 SIGINT → 強制 KeyboardInterrupt（避免 cleanup 卡住）
- **ScanContext** 中央 lifecycle 狀態（`cypulse/utils/scan_lifecycle.py`）：
  abort flag、temp files registry、deadline；module-level active context
  讓跨層模組（web_security/cloud_exposure）可註冊 temp 檔
- **`runner.run_analysis(..., on_module_done)`** / **`pipeline.run_discovery(..., on_step_done)`**
  callback 參數（向後相容預設 None），支援進度條
- **SIT 端到端整合測試**（`tests/sit/`）：
  - SIT-1 完整 scan flow（mock subprocess + HTTP，驗證 8 模組產出 + HTML 視覺化）
  - SIT-2 兩次 scan + diff + atomic write 韌性
  - SIT-3 timeout（exit 124）+ SIGINT（exit 130）端到端
  - 預設 `make test` 不跑（`-m 'not sit'`）；`make test-sit` 單獨執行

### Changed

- `cypulse/cli.py` scan 主流程抽出 `_execute_scan()`，外層 `try/except ScanAborted` 包裹
- `cypulse/analysis/web_security.py:_run_nuclei` 與 `cypulse/analysis/cloud_exposure.py:run`
  改在建立 tempfile 後立即 `register_temp_file()`，正常完成走 `os.unlink`，
  異常中斷走 `ctx.cleanup_temp_files`（雙重保險）
- `pyproject.toml`：新增 `[tool.pytest.ini_options].markers` 與 `addopts -m 'not sit'`
- `Makefile`：新增 `make test-sit` target

### Meta（守門測試擴充）

- 既有 308 → **331 unit tests pass + 7 SIT pass**（合計 +30）
- ScanContext 16 筆 unit（含 SIGINT handler、active context、cleanup tolerance）
- callback 機制 4 筆 unit（runner + pipeline）
- HTML 視覺化 3 筆 unit（confidence badge / low warning / failed sources）

---

## [0.3.0] - 2026-04-17

### Added

- **原子寫檔** `cypulse/utils/io.py`（`safe_write_json` / `safe_write_text`）
  - findings / assets / score / module_M*.json / report.html / CSV 全部採用
  - Ctrl-C / OOM / 寫入失敗不再留下半寫檔案（避免下次 diff 載入 crash）
- **來源狀態追蹤** `SourceStatus` 結構（見 [ADR-006](docs/adr/ADR-006-source-resilience-and-confidence.md)）
  - M1 / M2 / M6 / M8 每個外部來源（Shodan / HIBP / nuclei / s3scanner 等）獨立追蹤狀態
  - `ModuleResult.sources: list[SourceStatus]` 新欄位（default [] 相容舊資料）
- **信心分數**（Y 案）
  - `Score.confidence: float`（0.0~1.0）反映掃描整體覆蓋率
  - `Score.source_coverage: dict[str, float]` 各模組來源成功率
  - 總分仍以 100 為分母，跨掃描可比較；confidence 作為輔助指標
- **嚴格 status 門檻** `cypulse/analysis/base.determine_status`
  - 所有 active core 失敗 → `"error"`；任一 core 失敗 → `"partial"`；只 aux 失敗 → `"success"`
  - skipped（無 API key / 工具未安裝）不計入失敗

### Changed

- M2 `_check_shodan/greynoise/abuseipdb/ipapi` 回傳型別由 `Finding | None` 改為 `tuple[Finding | None, str | None]`（附 error 資訊）
- M6 `_check_hibp_public/credential_leaks/leakcheck` 同上
- M1 `_run_nuclei/testssl` 結果由 `list[Finding] | None` 轉換為 `SourceStatus` 追蹤
- `ScoreExplanation` 在 coverage < 1.0 時自動附加「部分來源未回應」info 訊息（deduction=0）
- **AnalysisModule `weight()` / `max_score()` 改為從 `WEIGHTS` 取預設值**（單一事實來源）
  - 移除 8 個模組類別的手寫 `weight()` / `max_score()` override
  - 消除 PDF 顯示 M7 「5/3」等模組代碼與 WEIGHTS 不同步的矛盾畫面
- **ADR-002 標註 `Superseded by ADR-004 / ADR-005`**：
  等級閾值改 A(90-100)/B(75-89)/C(60-74)/D(0-59)；
  M5 10%→8%、M7 5%→3%、新增 M8 4%。ADR-002 保留為歷史決策紀錄
- **CLI `scan --modules` 新增 module ID 驗證**：
  未知模組（如 `M9`）立即 err + exit 1，不再靜默忽略
- **`pyproject.toml` version** 0.1.0 → 0.3.0 對齊 CHANGELOG

### Fixed

- 修復 M2 Shodan 失敗時其他來源產出的 finding 無法追溯「為何只有 2/4 來源」的不透明問題
- 修復 HIBP timeout 靜默回傳 `[]` 與「真的沒外洩」無法區分的問題
- 修復 PDF/HTML 報告 M7「偽冒域名偵測」顯示 `5/3` 的矛盾（模組代碼殘留舊權重）
- 修復 CLI `scan --modules M9` 靜默忽略造成使用者誤以為 M9 有執行

### Meta（單一事實來源守門）

新增多道跨檔案一致性測試，未來漂移時 CI 會立刻攔下：
- `test_module_weight_matches_weights_py` / `test_module_name_matches_weights_py`
- `test_m1/m2/m6_source_defs_sum_to_one`（`_SOURCE_DEFS` 權重總和 == 1.0）
- `test_pyproject_version_matches_latest_changelog`（version ↔ CHANGELOG 同步）
- `test_grades_match_adr004`（GRADES ↔ ADR-004 閾值同步）
- `test_scan_invalid_module_id_rejected`（CLI 拒絕未知 module ID）

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
- M6 暗網帳號密碼外洩（LeakCheck 付費 + HIBP 免費 fallback）10%
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
