# ADR-006: 來源級韌性追蹤與信心分數機制

| 欄位 | 內容 |
|------|------|
| **狀態** | Accepted |
| **日期** | 2026-04-17 |
| **決策者** | CyPulse 開發團隊 |
| **影響範圍** | `cypulse/models/findings.py`、`cypulse/models/score.py`、`cypulse/analysis/{base,web_security,ip_reputation,darkweb,cloud_exposure}.py`、`cypulse/scoring/engine.py`、`cypulse/utils/io.py` |

---

## 背景

在執行期韌性審計中發現三類穩定性缺口：

1. **來源層級失敗不可見**：M2（ip_reputation）同時呼叫 Shodan / AbuseIPDB / GreyNoise / IP-API 四個外部來源，但每個 `_check_*` 方法失敗時靜默回傳空值。上層無法區分「Shodan 查完無弱點」與「Shodan API 掛掉」，分數因此可能含未被察覺的水分。
2. **信心分數缺失**：即使 M2 只有 2/4 來源成功（覆蓋率 50%），`max_score=15` 依舊不變，扣分邏輯照常運行，使用者無從判斷「這次掃描是否該重跑」。
3. **寫檔非原子性**：5 個 JSON/HTML 寫入點（assets / findings / module_M*.json / score / report.html）全都直接 `open(..., "w")`，Ctrl-C 或 OOM 中斷可能留下半寫檔案，下次 diff 載入時 crash。

---

## 決策

### 1. 來源狀態追蹤（SourceStatus）

每個有多資料源的分析模組（M1/M2/M6/M8）明確登記其來源清單與角色：

```python
@dataclass
class SourceStatus:
    source_id: str      # "shodan" / "hibp" / "nuclei" / "s3scanner" / ...
    role: str           # "core" | "auxiliary"
    weight: float       # 同模組內總和 = 1.0
    status: str         # "success" | "failed" | "skipped"
    error: str | None = None  # timeout / http_xxx / parse_error / ...
```

各模組的 `_check_*` 方法改回傳 `(result, error: str | None)` tuple，上層能準確區分成功/失敗/無資料三種情境。

**來源權重分配：**

| Module | Sources | Role/Weight |
|---|---|---|
| M1 (Web) | nuclei / testssl | core 0.6 / aux 0.4 |
| M2 (IP) | shodan, abuseipdb / greynoise, ip_api | core 0.35×2 / aux 0.15×2 |
| M6 (DarkWeb) | hibp / comb, leakcheck | core 0.5 / aux 0.25×2 |
| M8 (Cloud) | s3scanner | core 1.0（單一來源） |
| M3/M4/M5/M7 | — | 單工具，無 per-source 追蹤 |

### 2. 嚴格 status 門檻（使用者指定）

在 `cypulse/analysis/base.py` 新增共用 `determine_status()`：

- **所有 active core 都失敗** → `"error"`
- **任一 active core 失敗** → `"partial"`
- **只有 auxiliary 失敗，core 全成功** → `"success"`（信心分數會反映）
- `skipped` 狀態（無 API key、工具未安裝）不計入失敗，計算比例時排除

此門檻比過去更嚴格：M2 過去只要有任何 finding 就 `success`，現在 Shodan 掛掉就標記 `partial`。

### 3. 信心分數（Y 案）

新增 `Score.confidence: float` 與 `Score.source_coverage: dict[str, float]`：

```
單模組 coverage = Σ(success weight) / Σ(non-skipped weight)
整體 confidence = Σ(module coverage × WEIGHTS[mid].weight) / Σ(WEIGHTS[mid].weight)
```

**關鍵設計抉擇（Y 案 vs X 案）：**

採用 Y 案 — 總分（`Score.total`）仍為各模組 `score` 之和，滿分仍為 100。跨掃描可比較。`confidence` 作為輔助指標，低於 0.8 建議重跑。

捨棄 X 案（total 用 effective_max 當分母）—— 因為不同掃描的分母會浮動，歷史趨勢與差異比對會失真。

### 4. 原子寫檔（safe_write_json / safe_write_text）

`cypulse/utils/io.py` 提供兩個 helper：tmp 檔同目錄寫入 + `os.replace()` atomic rename。5 個寫入點全部採用。失敗時自動清除 tmp 檔、原檔維持不動。

---

## 後果

### 優點
- **透明性**：使用者能在 `score.json` 中看到每個模組的 coverage 與失效來源列表，判斷是否重跑
- **韌性**：單一外部 API 故障不會導致整個 scan 崩潰、分數歸零；只要有一個 active core 成功，其他來源仍能產出 finding（細粒度韌性）
- **可比性**：總分計算邏輯不變，歷史趨勢圖、diff 比對可直接使用（Y 案的主要收益）
- **資料完整性**：中斷不再毀檔，下次 diff 不會 crash

### 取捨
- **嚴格 status 門檻**代價是 `status` 欄位更常見到 `partial`/`error`，使用者需理解「error 不代表全面失敗，可能仍有 finding」
- **信心分數**需教育使用者「score=78 但 confidence=0.7 比 score=78 但 confidence=1.0 差」
- **來源 weight 配置**寫死在代碼（`_SOURCE_DEFS`）而非 config 檔，未來若使用者想調權重需修改代碼

### 不納入本決策
- Ctrl-C signal handler / 掃描全局 timeout → 留待 Cluster 3
- 來源失敗的 retry 策略 → 既有 `cypulse/utils/subprocess.py:run_cmd` 的 `max_retries` 機制已覆蓋 subprocess；HTTP 層重試待後續 ADR

---

## 相關
- ADR-002：七維度加權評分演算法（本決策擴充至八維度 + coverage）
- ADR-004：評分去重、等級線性化與補救建議
- ADR-005：M8 雲端資產暴露模組（M8 為單一 core 來源的代表案例）
- 審計紀錄：`/home/ubuntu/.claude/plans/asp-parallel-adleman.md`
