# ADR-008: 可觀察性、安全 log、CLI DX 強化

| 欄位 | 內容 |
|------|------|
| **狀態** | Accepted |
| **日期** | 2026-04-19 |
| **決策者** | CyPulse 開發團隊 |
| **影響範圍** | `cypulse/utils/{logging,diagnostics}.py`、`cypulse/automation/diff.py`、`cypulse/cli.py`、`cypulse/models/score.py` |

---

## 背景

Phase 1 完成「實際掃描體驗」HIGH 影響項後，Phase 2 鎖定 5 項 MED 影響的後勤/安全/DX 改善：

1. **secret 洩漏防線**：DEBUG log 可能印出工具命令含 API key（即使現在沒這種命令，沒守門 = 未來新增模組就會出事）
2. **錯誤訊息品質**：實測 `dnspython 太舊` 時，使用者只看到通用 ImportError，需要看 stderr 才能推斷修復方式
3. **觀察性**：同時跑多個 scan 的 log 混在一起無法追溯；發 issue 時無法附完整脈絡
4. **CLI DX**：使用者必須讀 README 才知道有哪些模組；新手誤觸 130 秒掃描無法預先驗證設定
5. **diff 韌性**：跨版本載入舊 scan 時 schema 不同 → 所有 finding 被誤判為 resolved

附帶補洞：Task F（atomic write）漏改的第 6 個寫入點 `diff.save_diff`。

---

## 決策

### 1. structlog `_mask_secrets` processor（防禦性 logging）

**選擇：** structlog processor 鏈中加 `_mask_secrets`，掛在 `add_log_level` 之後、renderer 之前。

**Masking 規則：**
- `_SENSITIVE_KEY_PATTERN`（regex, case-insensitive）：`api_key | token | password | passwd | secret | webhook | authorization | bearer`
- dict key 含 sensitive 字眼 → value 遞迴 mask（含 nested dict/list）
- list 中前一元素含 sensitive 字眼 → 後一元素被 mask（典型 cmd args 模式 `[..., "--token", "secret"]`）
- 值長度 > 8 保留前 4 字 + `***`（便於 debug 比對）；≤ 8 整個變 `***`

**捨棄方案：**
- **不 mask click.echo**：CLI 直接寫的字串責任在 CLI 層，且 CLI 不會 dump config dict
- **不 mask subprocess args 本身**：只 mask log 表現；命令仍正常執行

### 2. `format_error()` 錯誤分類器

**選擇：** `cypulse/utils/diagnostics.py:format_error(exc) -> str` 將常見 Exception 分類並回傳「修復建議」。

**已知模式：**
- `ImportError("dns.nameserver")` → 提示 `pip install --upgrade dnspython>=2.4`
- `subprocess.TimeoutExpired` → 提示 `config.scan.timeout_seconds`
- `requests.Timeout / ConnectionError` → 提示重試 / 網路檢查
- `FileNotFoundError + 含已知工具名` → 提示 `docs/DEPLOY_SPEC.md`
- `DiffSchemaError` → 提示重新掃描
- `ScanAborted` → 提示部分結果已保存
- Fallback：含 `type` + `str(exc)` 確保不吃掉原始錯誤

**捨棄方案：**
- **structlog exception processor**：只能格式化 stack trace 不能給可行動建議
- **CLI 內 if/elif 鏈**：散在 except 區塊難維護

### 3. scan_id contextvar + `--export-logs`

**選擇：** CLI scan 開頭 `bind_contextvars(scan_id=uuid12, domain=...)`；structlog `merge_contextvars` 已啟用，所有 log 自動含這兩個 key。

**`--export-logs PATH`** 用 in-memory log capture processor 收集所有 event，scan 結束時寫成 jsonl。capture processor 插在 `_mask_secrets` 之後，確保 buffer 也是 mask 結果。

**`Score.scan_id`** 新增（dataclass `default=None`，相容舊資料）。

**捨棄方案：**
- **logfile 全域配置**：使用者不一定想要 file log；scan-scoped 比較乾淨
- **request_id 風格中介層**：CyPulse 不是 web app

### 4. CLI `list-modules` + `--dry-run`

**選擇：**
- `cypulse list-modules` 印 WEIGHTS 表格 + 總計欄位（驗證 100% / 100 滿分）
- `cypulse scan --dry-run` 預檢：domain 格式 ✓、列模組、檢查工具/API key 可用性、不執行 Phase 1-5

**捨棄方案：**
- **不做 list-tools**：工具清單已在 `--dry-run` 顯示
- **不做 list-rules / list-finding-types**：findings 數量太多，list 沒意義

### 5. diff schema 驗證（DiffSchemaError）

**選擇：** 新/舊 scan 區分處理：
- **新 scan** schema 缺鍵 → raise `DiffSchemaError`（代碼 bug，必須失敗）
- **舊 scan** schema 缺鍵 → 不 raise，回傳含警示 alert 的空 DiffReport
  （cron 排程不被舊資料拖垮；alert 提示「建議重新掃描以建立新版基準」）

**必要 key：**
- `score.json`: `{total, dimensions}`
- `findings.json`: `{domain, modules}`

### 6. diff atomic write（補 Task F 漏洞）

`save_diff` 改用 `safe_write_json` —— 與 Task F 既有 5 個寫入點對齊。

---

## 後果

### 優點
- **安全**：DEBUG log 即使誤放 secret 也會 mask；任何新模組自動受益
- **使用者排障能力**：dnspython 太舊類錯誤直接給修復指令
- **觀察性**：每個 scan 有 uuid scan_id 可跨 log 追溯；`--export-logs` 一鍵附 issue
- **DX**：list-modules / dry-run 大幅降低新手上手成本
- **韌性**：跨版本 diff 不再靜默產出錯誤 alert
- **資料完整性**：第 6 個寫入點補上 atomic write

### 取捨
- **mask 規則保守**：保留前 4 字便於 debug；極短 token 整個變 `***`，無法 partial 比對
- **dry-run 不檢查網路**：避免 dry-run 也耗時；只檢查工具/API key 可用性
- **scan_id 12 字元**：uuid hex 共 32 字元，取前 12 確保 collision 機率極低（~10^14 種組合）但 log 可讀

### 不納入本決策
- 多 domain 並行 → Phase 3
- scan resume → Phase 3
- pip-audit / Dockerfile 安全加固 → Phase 3
- release 自動化 → Phase 3

---

## 相關
- ADR-006：來源級韌性追蹤與信心分數
- ADR-007：掃描 Lifecycle + 進度顯示
- Task F commit `299ed4f`：safe_write_json（本次補第 6 處）
- Task R/S/V/Q/T/U/W commits：本 ADR 對應實作
