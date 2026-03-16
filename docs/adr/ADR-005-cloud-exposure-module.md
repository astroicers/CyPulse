# ADR-005: M8 雲端資產暴露模組設計決策

| 欄位 | 內容 |
|------|------|
| **狀態** | Accepted |
| **日期** | 2026-03-16 |
| **決策者** | CyPulse 開發團隊 |
| **影響範圍** | `cypulse/analysis/cloud_exposure.py`（新增）、`cypulse/scoring/weights.py`、`cypulse/analysis/runner.py` |

---

## 背景

CyPulse M1-M7 完全未覆蓋雲端儲存桶（Cloud Bucket）暴露風險。雲端 bucket 公開讀寫是高頻 EASM 事件，常見於 S3、GCS、Azure Blob Storage，屬於資產暴露最直接的形式之一。

現有模組分析：

- M1（網站安全）：只掃 HTTP Header 與 TLS，不處理 bucket 命名
- M2（IP 信譽）：只評估 IP 層級風險
- M3-M7：均不涉及雲端物件儲存

此為 CyPulse 目前最大的覆蓋缺口。

---

## 決策

### 1. 新增 M8（雲端資產暴露）模組

**決策**：新增獨立模組 `CloudExposureModule`（M8），使用 s3scanner 工具掃描從 domain 衍生的常見 bucket 名稱。

**理由**：
- 獨立模組符合現有 AnalysisModule ABC 架構，不影響 M1-M7
- s3scanner 為 Python pip 套件，跨平台、無需 API key、支援多雲（S3/GCS/Azure）
- Fallback 策略一致：s3scanner 未安裝 → `status=partial`，不中斷其他模組

### 2. WEIGHTS 調整方案

原 M1-M7 總計 100%/100pt，加入 M8 需從現有模組借調：

| 模組 | 舊 weight | 新 weight | 舊 max_score | 新 max_score |
|------|-----------|-----------|--------------|--------------|
| M5（郵件安全）| 10% | 8% | 10 | 8 |
| M7（偽冒域名偵測）| 5% | 3% | 5 | 3 |
| M8（雲端資產暴露）| — | 4% | — | 4 |

調整依據：
- M5 郵件安全覆蓋（SPF/DMARC/DKIM）已相對成熟，降低 2% 影響有限
- M7 偽冒域名為輔助指標，降低 2% 不影響核心評估
- M8 新增 4% 足以體現雲端暴露對整體曝險評分的影響

總計：25+15+20+15+8+10+3+4 = 100 ✓，權重總和 = 1.00 ✓

### 3. Bucket 命名衍生策略

從 `domain` 衍生 7 種常見 bucket 命名模式（`{prefix}`, `www-{prefix}`, `media-{prefix}`, `assets-{prefix}`, `cdn-{prefix}`, `backup-{prefix}`, `static-{prefix}`），以 `.` 轉 `-` 為前綴。

**理由**：覆蓋最常見的命名習慣，同時避免過多 bucket 名稱造成掃描超時。

### 4. Fallback 策略

s3scanner 未安裝時：
- 回傳 `status=partial`
- 附加 `severity=info` 的 finding 說明原因
- 不拋出例外，不影響其他模組計分

---

## 替代方案

### 替代方案 A：整合進 M1 模組

**棄用原因**：M1 已包含 HTTP Header、TLS、Nuclei、testssl.sh 四個子系統，再加入雲端掃描會使模組過度膨脹，且責任不清晰。獨立 M8 更易測試、替換。

### 替代方案 B：使用 bucket-finder（Ruby 工具）

**棄用原因**：需要額外安裝 Ruby 環境，跨平台相容性差。s3scanner 為 Python pip 套件，與現有技術棧一致，`pip install s3scanner` 即可。

### 替代方案 C：使用付費 API（如 Shodan Facets）

**棄用原因**：CyPulse 設計原則為「全部免費、無需付費 key」，付費 API 違反此原則，且增加使用者操作成本。

---

## 影響

- `cypulse/scoring/weights.py`：M5 max_score 10→8，M7 max_score 5→3，新增 M8
- `cypulse/analysis/runner.py`：ALL_MODULES 清單加入 `CloudExposureModule`
- `tests/test_scoring/test_weights.py`：更新受 max_score 變更影響的邊界值測試
- 測試覆蓋率預計維持 ≥ 90%

## Tech Debt

- M8 目前僅掃描 S3 命名模式，未來可擴展至 GCS bucket 命名（`storage.googleapis.com/{bucket}`）
- bucket 命名模式為靜態清單，未來可從 HTTP 回應或 JavaScript 中動態提取
