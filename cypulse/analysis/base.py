from __future__ import annotations
from abc import ABC, abstractmethod
from cypulse.models import Assets, ModuleResult


class AnalysisModule(ABC):

    @abstractmethod
    def module_id(self) -> str:
        ...

    @abstractmethod
    def module_name(self) -> str:
        ...

    @abstractmethod
    def weight(self) -> float:
        ...

    @abstractmethod
    def max_score(self) -> int:
        ...

    @abstractmethod
    def run(self, assets: Assets) -> ModuleResult:
        ...
