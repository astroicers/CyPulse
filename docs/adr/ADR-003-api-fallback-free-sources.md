# ADR-003: 免費 API Fallback 機制設計

| 欄位 | 內容 |
|------|------|
| **狀態** | Accepted |
| **日期** | 2026-03-16 |
| **決策者** | CyPulse 開發團隊 |
| **影響範圍** | `cypulse/analysis/ip_reputation.py`, `cypulse/analysis/darkweb.py` |

---

## 背景

CyPulse 目標是以 100% 開源免費工具實作完整 EASM 能力（見 ADR-001）。然而 M2（IP 信譽）與 M6（暗網憑證外洩）的最高品質資料源（AbuseIPDB、LeakCheck）需付費 API Key。

若強制要求 API Key，會讓零成本使用場景完全無法執行這兩個模組，違背開源免費目標。

## 決策

實作**有序 Fallback 鏈**：依環境變數中的 API Key 可用性，自動選擇最佳資料源。

### M2 IP 信譽 Fallback 鏈

```
1. AbuseIPDB (付費，ABUSEIPDB_API_KEY)
   ↓ 無 API Key 或請求失敗
2. AlienVault OTX (免費，無需 Key)
   ↓ 請求失敗或 rate limit
3. 回傳 partial_result，status="partial"
```

### M6 暗網憑證外洩 Fallback 鏈

```
1. LeakCheck (付費，LEAKCHECK_API_KEY)
   ↓ 無 API Key 或請求失敗
2. HIBP Have I Been Pwned (免費，有 rate limit)
   ↓ 請求失敗或 rate limit
3. 回傳 partial_result，status="partial"
```

### Fallback 行為規則

- 每次 fallback 均記錄 WARNING 日誌，說明使用的替代源
- `ModuleResult.raw_data` 包含 `data_source` 欄位，標明實際使用的資料源
- `status="partial"` 時，報告中顯示免責聲明
- 不會因 fallback 而拋出例外（靜默降級）

## 替代方案

| 方案 | 捨棄原因 |
|------|---------|
| **強制要求 API Key** | 違背開源免費目標，提高使用門檻 |
| **完全移除付費 API** | 無法讓有 Key 的用戶獲得更高精準度 |
| **全部標記 unavailable** | 讓 M2/M6 完全沒有輸出，影響評分可信度 |

## 影響

- `cypulse/analysis/ip_reputation.py`：實作 AbuseIPDB → AlienVault OTX fallback
- `cypulse/analysis/darkweb.py`：實作 LeakCheck → HIBP fallback
- `.env.example`：新增 `ABUSEIPDB_API_KEY`、`LEAKCHECK_API_KEY` 說明
- 測試：需包含有/無 API Key 兩種情境的 mock 測試

## 技術債

- AlienVault OTX 免費版有每日 API 呼叫限制（10,000 次/天），高頻使用場景需注意
- HIBP 免費版有 rate limit（1500ms 間隔），大量 IP 掃描時速度較慢
