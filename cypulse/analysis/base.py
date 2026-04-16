from __future__ import annotations
from abc import ABC, abstractmethod
from cypulse.models import Assets, ModuleResult, SourceStatus
from cypulse.scoring.weights import WEIGHTS


class AnalysisModule(ABC):
    """分析模組基底類別。

    子類別必須實作 module_id()、module_name()、run()。
    weight() 和 max_score() 預設從 WEIGHTS（scoring/weights.py）取值，
    確保權重為單一事實來源；若子類別覆寫時必須手動維護同步。
    """

    @abstractmethod
    def module_id(self) -> str:
        ...

    @abstractmethod
    def module_name(self) -> str:
        ...

    def weight(self) -> float:
        """預設從 WEIGHTS 取，避免模組代碼與 weights.py 漂移。"""
        return WEIGHTS[self.module_id()]["weight"]

    def max_score(self) -> int:
        """預設從 WEIGHTS 取，避免模組代碼與 weights.py 漂移。"""
        return WEIGHTS[self.module_id()]["max_score"]

    @abstractmethod
    def run(self, assets: Assets) -> ModuleResult:
        ...


def determine_status(sources: list[SourceStatus]) -> str:
    """依 sources 狀態決定 ModuleResult.status。

    規則：
    - 無 sources → "success"（模組無 per-source 概念，如 M3/M4/M5/M7）
    - skipped 視為未啟用，計算比例時排除
    - 所有「啟用中」core 都失敗 → "error"
    - 部分 core 失敗 → "partial"
    - core 全部成功 → "success"（auxiliary 失敗會在信心分數反映）
    """
    if not sources:
        return "success"
    active_cores = [s for s in sources if s.role == "core" and s.status != "skipped"]
    if not active_cores:
        # 所有 core 都 skipped（例如沒任何 API key）→ 不算失敗
        return "success"
    failed_active_cores = [s for s in active_cores if s.status == "failed"]
    if len(failed_active_cores) == len(active_cores):
        return "error"
    if failed_active_cores:
        return "partial"
    return "success"
