import pytest
from cypulse.analysis.base import AnalysisModule
from cypulse.analysis.runner import ALL_MODULES
from cypulse.scoring.weights import WEIGHTS
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


@pytest.mark.parametrize("module_cls", ALL_MODULES)
def test_module_weight_matches_weights_py(module_cls):
    """每個模組的 weight() / max_score() 必須與 WEIGHTS（scoring/weights.py）同步。

    過去 ADR-005 調整 M5(10→8)、M7(5→3) 與新增 M8(4) 時只改了 weights.py，
    模組代碼殘留舊值，造成報告 HTML/PDF 顯示 5/3 等矛盾畫面。
    """
    mod = module_cls()
    mid = mod.module_id()
    assert mid in WEIGHTS, f"{mid} 未在 WEIGHTS 中定義"
    expected = WEIGHTS[mid]
    assert mod.weight() == expected["weight"], (
        f"{mid}.weight()={mod.weight()} 與 WEIGHTS[{mid}].weight={expected['weight']} 不一致"
    )
    assert mod.max_score() == expected["max_score"], (
        f"{mid}.max_score()={mod.max_score()} "
        f"與 WEIGHTS[{mid}].max_score={expected['max_score']} 不一致"
    )


@pytest.mark.parametrize("module_cls", ALL_MODULES)
def test_module_name_matches_weights_py(module_cls):
    """每個模組的 module_name() 必須與 WEIGHTS[mid].name 完全一致。

    未來若任一方改動名稱沒同步，會造成報告標題與 WEIGHTS 定義不符
    （例如 dim-card 顯示 WEIGHTS["M6"].name，module 詳情顯示 module_name()）。
    """
    mod = module_cls()
    mid = mod.module_id()
    expected_name = WEIGHTS[mid]["name"]
    assert mod.module_name() == expected_name, (
        f"{mid}.module_name()={mod.module_name()!r} "
        f"與 WEIGHTS[{mid}].name={expected_name!r} 不一致"
    )
