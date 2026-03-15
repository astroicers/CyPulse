import pytest
from cypulse.analysis.base import AnalysisModule
from cypulse.models import Assets, ModuleResult


def test_analysis_module_is_abstract():
    with pytest.raises(TypeError):
        AnalysisModule()


def test_analysis_module_concrete_implementation():
    class ConcreteModule(AnalysisModule):
        def module_id(self) -> str:
            return "M_TEST"

        def module_name(self) -> str:
            return "測試模組"

        def weight(self) -> float:
            return 0.1

        def max_score(self) -> int:
            return 10

        def run(self, assets: Assets) -> ModuleResult:
            return ModuleResult(
                module_id="M_TEST",
                module_name="測試模組",
                score=10,
                max_score=10,
                findings=[],
            )

    mod = ConcreteModule()
    assert mod.module_id() == "M_TEST"
    assert mod.module_name() == "測試模組"
    assert mod.weight() == 0.1
    assert mod.max_score() == 10
