# 常見問題排查（Troubleshooting）

---

## 工具相關

### subfinder / amass / naabu 找不到指令

**症狀：** `FileNotFoundError: [Errno 2] No such file or directory: 'subfinder'`

**解法：** 使用 Docker 執行（已預裝所有工具）：

```bash
docker-compose run --rm cypulse scan example.com
```

若要本機安裝（需要 Go 1.21+）：

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@master
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

---

### Nuclei 無法執行或 findings 為空

**症狀：** M1 模組掃描後 Nuclei findings 為空，或出現 `nuclei: command not found`

**解法：**

```bash
# 安裝 Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# 更新模板（首次使用必須執行）
nuclei -update-templates

# 確認版本 ≥ 3.0
nuclei -version
```

---

### M8 雲端暴露顯示 `status: partial` / `s3scanner not installed`

**症狀：** 掃描結果中 M8 模組 status 為 partial、finding 說明 "s3scanner 未安裝"。

**原因：** `cypulse/analysis/cloud_exposure.py` 呼叫 `check_tool("s3scanner")` 失敗。

**解法：**

使用 Docker 推薦，image 已預裝。若本機執行：

```bash
# 下載 s3scanner Go binary（官方 release）
curl -L https://github.com/sa7mon/S3Scanner/releases/latest/download/s3scanner-linux-amd64 \
  -o /usr/local/bin/s3scanner
chmod +x /usr/local/bin/s3scanner
s3scanner --help
```

參考 [ADR-005](adr/ADR-005-cloud-exposure-module.md) 了解模組設計決策。

---

### testssl.sh 未找到 / M1 深度 TLS 掃描未執行

**症狀：** M1 finding 出現 "testssl.sh 未安裝，TLS 深度掃描未執行"。

**解法：** Docker 已預裝；本機可依 Dockerfile 流程手動安裝 testssl.sh 3.2 版，或接受 httpx 基本 TLS 檢測。

---

## API Key 相關

### 分析結果顯示 "partial" 或資料來源為免費版

**說明：** CyPulse 在無 API Key 時自動 fallback 至免費替代源。這是預期行為，不影響工具正常執行，但分析精準度可能略有差異。

**設定 API Key：**

```bash
cp .env.example .env
# 編輯 .env，填入以下 Key：
# ABUSEIPDB_API_KEY=your_key   （M2 IP 信譽，https://www.abuseipdb.com/）
# LEAKCHECK_API_KEY=your_key   （M6 暗網憑證，https://leakcheck.io/）
```

---

## PDF 報告相關

### PDF 輸出中文顯示為方塊或亂碼

**症狀：** 報告中文字型無法正確顯示

**解法：**

Docker 環境已預裝字型，應不會發生此問題。若本機執行：

```bash
# Ubuntu / Debian
sudo apt-get install fonts-noto-cjk

# macOS (Homebrew)
brew install --cask font-noto-sans-cjk-tc
```

安裝後重新執行掃描即可。

---

### weasyprint 安裝失敗

**症狀：** `pip install weasyprint` 出現編譯錯誤

**解法：** 安裝系統依賴：

```bash
# Ubuntu / Debian
sudo apt-get install libpango-1.0-0 libpangoft2-1.0-0 libpangocairo-1.0-0

# macOS
brew install pango
```

---

## Docker 相關

### 掃描結果未保留（容器重啟後 data/ 清空）

**解法：** 確認 `docker-compose.yml` 的 volume 掛載：

```yaml
volumes:
  - ./data:/app/data
  - ./.env:/app/.env:ro
```

確認 `./data` 目錄存在且有寫入權限：

```bash
mkdir -p data
chmod 755 data
```

---

### Docker 容器內工具版本過舊

**解法：** 重新 build image：

```bash
make build
# 或
docker-compose build --no-cache
```

---

## 測試相關

### 測試失敗：subprocess timeout 或工具找不到

**說明：** 單元測試中的 subprocess 呼叫均應被 mock，不應呼叫真實工具。

**排查步驟：**

```bash
# 確認 conftest.py fixtures 正常載入
pytest tests/ -v --fixtures | grep mock

# 單獨執行失敗的測試
make test-filter FILTER=test_subfinder
```

若問題持續，確認 `tests/conftest.py` 中的 fixture scope 設定正確。

---

## 日誌與偵錯

啟用 DEBUG 日誌取得詳細輸出：

```bash
# 本機執行
CYPULSE_LOG_LEVEL=DEBUG cypulse scan example.com

# Docker 執行
docker-compose run --rm -e CYPULSE_LOG_LEVEL=DEBUG cypulse scan example.com
```

日誌輸出至 stdout，可搭配 `tee` 儲存：

```bash
CYPULSE_LOG_LEVEL=DEBUG cypulse scan example.com 2>&1 | tee debug.log
```
