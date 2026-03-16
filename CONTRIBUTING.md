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
```

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

1. 在 `cypulse/analysis/` 建立新模組，實作 `AnalysisModule` ABC：

   ```python
   from cypulse.analysis.base import AnalysisModule
   from cypulse.models import Assets, ModuleResult

   class MyModule(AnalysisModule):
       def module_id(self) -> str: return "M8"
       def module_name(self) -> str: return "模組名稱"
       def weight(self) -> float: return 0.05
       def max_score(self) -> int: return 5
       def run(self, assets: Assets) -> ModuleResult: ...
   ```

2. 在 `tests/test_analysis/` 補齊測試
3. 在 `cypulse/scoring/weights.py` 新增權重定義
4. 更新 `docs/SRS.md`（新增 FR）與 `docs/SDS.md`（新增設計）
5. 若影響架構，建立新 ADR：`make adr-new TITLE="..."`

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
