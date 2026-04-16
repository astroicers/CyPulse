# Contributing to CyPulse

感謝你對 CyPulse 的貢獻！本文件說明如何參與開發。

---

## 開發環境建置

```bash
git clone https://github.com/your-org/cypulse.git
cd cypulse
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# 安裝 pre-commit hook（flake8 + black --check + hygiene）
pip install pre-commit
pre-commit install
```

**為何需要 pre-commit？** 本專案的 `.pre-commit-config.yaml` 會在每次 commit
前執行 flake8（對齊 `.flake8` 的 100 字元設定）、black --check 與基本 hygiene
（trailing whitespace、large files、private-key scanner）。GitHub Actions CI
同樣會跑這些檢查，本地先通過能避免 CI 失敗。

## 開發規範

- **語言**：Python 3.10+
- **命名**：snake_case
- **Commit**：[Conventional Commits](https://www.conventionalcommits.org/)（`feat:`, `fix:`, `docs:`, `test:`, `refactor:`）
- **分支策略**：GitHub Flow（從 main 開 feature branch，PR 合回 main）
- **註解語言**：繁體中文

## 測試

所有 PR 必須包含對應測試（TDD 優先）：

```bash
make test          # 執行全部測試
make coverage      # 確認覆蓋率 ≥ 80%
make lint          # 程式碼風格檢查
```

## 新增安全分析模組

目前已有 M1–M8。若要擴充至 M9：

1. 在 `cypulse/analysis/` 建立新模組，實作 `AnalysisModule` ABC：

   ```python
   from cypulse.analysis.base import AnalysisModule
   from cypulse.models import Assets, ModuleResult

   class MyModule(AnalysisModule):
       def module_id(self) -> str: return "M9"
       def module_name(self) -> str: return "模組名稱"
       def weight(self) -> float: return 0.02  # 新模組會從既有模組借調權重
       def max_score(self) -> int: return 2
       def run(self, assets: Assets) -> ModuleResult: ...
   ```

2. 在 `tests/test_analysis/` 補齊測試（mock 所有外部呼叫）
3. 在 `cypulse/scoring/weights.py` 新增權重定義，確保 WEIGHTS 總和仍為 1.0
4. 更新 `docs/SRS.md`（新增 FR）與 `docs/SDS.md`（新增設計）
5. 建立 ADR 記錄權重借調決策：`make adr-new TITLE="..."`
6. 更新 `ROADMAP.yaml`（新增 task）與 `README.md`/`CHANGELOG.md`

## Pull Request 流程

1. Fork → 建 feature branch
2. 實作 + 測試（覆蓋率不得下降）
3. `make lint` 通過
4. PR 標題遵循 Conventional Commits
5. 描述說明改動動機與測試方式

## 問題回報

請使用 GitHub Issues，並提供：

- CyPulse 版本（`cypulse --version`）
- 作業系統與 Python 版本
- 最小重現步驟
- 實際 vs 預期行為

## 相關文件

- [SRS.md](docs/SRS.md) — 功能需求規格
- [SDS.md](docs/SDS.md) — 系統設計規格
- [docs/adr/](docs/adr/) — 架構決策記錄
