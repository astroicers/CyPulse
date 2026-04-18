# AI-SOP-Protocol — Makefile
# 目的：專案層級設定 + 載入 ASP targets
# 使用方式：在 include 之前加入專案自訂 targets

APP_NAME ?= CyPulse
VERSION  ?= latest

# --- 專案自訂 targets 請寫在此區塊 ---

# 系統整合測試（SIT）：跨 phase 端到端驗證
# 預設 `make test` 不跑（較慢、會 spawn 子進程）；發版前手動執行
.PHONY: test-sit
test-sit:
	@echo "🔬 Running SIT (System Integration Tests)..."
	@pytest tests/sit -m sit --override-ini="addopts=-m sit -v --tb=short"


# ASP targets（勿刪除此行）
-include .asp/Makefile.inc
