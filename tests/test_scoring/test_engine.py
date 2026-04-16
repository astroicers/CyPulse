import os
import json
import tempfile
from cypulse.scoring.engine import ScoringEngine, save_score
from cypulse.scoring.weights import get_grade
from cypulse.models import Findings, ModuleResult, Finding, Score, SourceStatus


class TestGetGrade:
    def test_grade_a(self):
        assert get_grade(95) == "A"
        assert get_grade(90) == "A"
        assert get_grade(100) == "A"

    def test_grade_b(self):
        assert get_grade(85) == "B"
        assert get_grade(80) == "B"
        assert get_grade(89) == "B"

    def test_grade_c(self):
        assert get_grade(74) == "C"
        assert get_grade(70) == "C"
        assert get_grade(60) == "C"

    def test_grade_d(self):
        assert get_grade(59) == "D"
        assert get_grade(0) == "D"
        assert get_grade(30) == "D"


class TestScoringEngine:
    def _make_findings(self, scores: dict[str, tuple[int, int]]) -> Findings:
        modules = []
        for mid, (score, max_score) in scores.items():
            deduction = max_score - score
            findings_list = []
            if deduction > 0:
                findings_list.append(Finding(
                    severity="medium",
                    title=f"Test finding for {mid}",
                    description="test",
                    score_impact=deduction,
                ))
            modules.append(ModuleResult(
                module_id=mid,
                module_name=f"Module {mid}",
                score=score,
                max_score=max_score,
                findings=findings_list,
                execution_time=1.0,
            ))
        return Findings(domain="example.com", timestamp="test", modules=modules)

    def test_perfect_score(self):
        findings = self._make_findings({
            "M1": (25, 25), "M2": (15, 15), "M3": (20, 20),
            "M4": (15, 15), "M5": (10, 10), "M6": (10, 10), "M7": (5, 5),
        })
        engine = ScoringEngine()
        score = engine.calculate(findings)
        assert score.total == 100
        assert score.grade == "A"
        assert len(score.explanations) == 0

    def test_partial_score(self):
        findings = self._make_findings({
            "M1": (18, 25), "M2": (15, 15), "M3": (15, 20),
            "M4": (12, 15), "M5": (8, 10), "M6": (7, 10), "M7": (3, 5),
        })
        engine = ScoringEngine()
        score = engine.calculate(findings)
        assert score.total == 78
        assert score.grade == "B"
        assert len(score.explanations) > 0

    def test_zero_score(self):
        findings = self._make_findings({
            "M1": (0, 25), "M2": (0, 15), "M3": (0, 20),
            "M4": (0, 15), "M5": (0, 10), "M6": (0, 10), "M7": (0, 5),
        })
        engine = ScoringEngine()
        score = engine.calculate(findings)
        assert score.total == 0
        assert score.grade == "D"

    def test_explain(self):
        findings = self._make_findings({"M1": (20, 25)})
        engine = ScoringEngine()
        score = engine.calculate(findings)
        exps = engine.explain(score)
        assert len(exps) == 1
        assert exps[0].module_id == "M1"

    def test_error_module_score_zero(self):
        """Modules with error status should contribute 0 and generate explanation."""
        modules = [
            ModuleResult(module_id="M1", module_name="Web Security", score=0,
                         max_score=25, findings=[], execution_time=0.0, status="error"),
            ModuleResult(module_id="M2", module_name="IP Reputation", score=15,
                         max_score=15, findings=[], execution_time=0.0, status="success"),
        ]
        findings = Findings(domain="example.com", timestamp="test", modules=modules)
        engine = ScoringEngine()
        score = engine.calculate(findings)
        assert score.total == 15
        assert score.dimensions["M1"] == 0
        assert any(e.module_id == "M1" for e in score.explanations)

    def test_partial_module_has_explanation(self):
        """Modules with partial status and reduced score should generate explanation."""
        modules = [
            ModuleResult(module_id="M1", module_name="Web Security", score=20,
                         max_score=25, findings=[], execution_time=0.0, status="partial"),
        ]
        findings = Findings(domain="example.com", timestamp="test", modules=modules)
        engine = ScoringEngine()
        score = engine.calculate(findings)
        assert score.total == 20
        assert len(score.explanations) == 1
        assert "未完成檢測" in score.explanations[0].reason


class TestSaveScore:
    def test_save_and_read(self):
        score = Score(total=78, grade="C", dimensions={"M1": 18}, explanations=[])
        with tempfile.TemporaryDirectory() as tmpdir:
            save_score(score, tmpdir)
            path = os.path.join(tmpdir, "score.json")
            assert os.path.isfile(path)
            with open(path) as f:
                data = json.load(f)
            assert data["total"] == 78
            assert data["grade"] == "C"


class TestConfidence:
    """Task H：信心分數（Y 案）測試。"""

    def _make_module(self, mid, score, max_score, sources=None):
        return ModuleResult(
            module_id=mid, module_name=mid, score=score, max_score=max_score,
            findings=[], raw_data={}, execution_time=0.0,
            status="success",
            sources=sources or [],
        )

    def test_all_sources_success_confidence_is_1(self):
        """全部來源都成功時，confidence=1.0。"""
        modules = [
            self._make_module("M2", 15, 15, sources=[
                SourceStatus("shodan", "core", 0.35, "success"),
                SourceStatus("abuseipdb", "core", 0.35, "success"),
                SourceStatus("greynoise", "auxiliary", 0.15, "success"),
                SourceStatus("ip_api", "auxiliary", 0.15, "success"),
            ]),
        ]
        findings = Findings(domain="x", timestamp="t", modules=modules)
        score = ScoringEngine().calculate(findings)
        assert score.confidence == 1.0
        assert score.source_coverage["M2"] == 1.0

    def test_partial_source_failure_reduces_confidence(self):
        """Shodan 失敗（core 0.35）→ M2 覆蓋率 0.65，但總分不變（Y 案關鍵）。"""
        modules = [
            self._make_module("M2", 15, 15, sources=[
                SourceStatus("shodan", "core", 0.35, "failed", "timeout"),
                SourceStatus("abuseipdb", "core", 0.35, "success"),
                SourceStatus("greynoise", "auxiliary", 0.15, "success"),
                SourceStatus("ip_api", "auxiliary", 0.15, "success"),
            ]),
            self._make_module("M3", 20, 20),  # 無 sources → 視為 1.0
        ]
        findings = Findings(domain="x", timestamp="t", modules=modules)
        score = ScoringEngine().calculate(findings)
        # M2 coverage = 0.65
        assert abs(score.source_coverage["M2"] - 0.65) < 1e-6
        assert score.source_coverage["M3"] == 1.0
        # 總分為各模組 score 之和（不受 coverage 影響）
        assert score.total == 15 + 20 == 35
        # 信心分數 = 加權平均（用 WEIGHTS 的權重）
        # 計算範圍只看實際出現的模組，confidence 應 < 1.0
        assert score.confidence < 1.0
        assert score.confidence > 0.8

    def test_skipped_sources_excluded_from_coverage(self):
        """skipped 不計入覆蓋率分母（例如沒 API key）。"""
        modules = [
            self._make_module("M2", 15, 15, sources=[
                SourceStatus("shodan", "core", 0.35, "success"),
                SourceStatus("abuseipdb", "core", 0.35, "skipped", "no_api_key"),
                SourceStatus("greynoise", "auxiliary", 0.15, "success"),
                SourceStatus("ip_api", "auxiliary", 0.15, "success"),
            ]),
        ]
        findings = Findings(domain="x", timestamp="t", modules=modules)
        score = ScoringEngine().calculate(findings)
        # 分母：0.35 + 0.15 + 0.15 = 0.65；分子：0.35 + 0.15 + 0.15 = 0.65
        # coverage = 1.0（skipped 排除後全部成功）
        assert score.source_coverage["M2"] == 1.0

    def test_all_sources_failed_zero_coverage(self):
        """所有來源失敗 → coverage = 0.0。"""
        modules = [
            self._make_module("M2", 0, 15, sources=[
                SourceStatus("shodan", "core", 0.35, "failed"),
                SourceStatus("abuseipdb", "core", 0.35, "failed"),
                SourceStatus("greynoise", "auxiliary", 0.15, "failed"),
                SourceStatus("ip_api", "auxiliary", 0.15, "failed"),
            ]),
        ]
        findings = Findings(domain="x", timestamp="t", modules=modules)
        score = ScoringEngine().calculate(findings)
        assert score.source_coverage["M2"] == 0.0

    def test_confidence_weighted_by_module_weight(self):
        """M1 權重 25%，若 M1 coverage=0.6 且其他模組 coverage=1.0，
        confidence 應 ≈ 1 - (0.4 × 0.25) = 0.9。"""
        modules = [
            self._make_module("M1", 25, 25, sources=[
                SourceStatus("nuclei", "core", 0.6, "failed"),
                SourceStatus("testssl", "auxiliary", 0.4, "success"),
            ]),
            self._make_module("M3", 20, 20),
            self._make_module("M4", 15, 15),
        ]
        findings = Findings(domain="x", timestamp="t", modules=modules)
        score = ScoringEngine().calculate(findings)
        # M1 coverage = 0.4（只有 testssl 成功）
        assert abs(score.source_coverage["M1"] - 0.4) < 1e-6
        # 信心 = (0.4 × 0.25 + 1.0 × 0.20 + 1.0 × 0.15) / (0.25 + 0.20 + 0.15)
        #      = (0.10 + 0.20 + 0.15) / 0.60 = 0.45 / 0.60 = 0.75
        assert abs(score.confidence - 0.75) < 1e-6

    def test_explanation_added_when_coverage_below_1(self):
        """coverage < 1.0 時應有 info-level explanation。"""
        modules = [
            self._make_module("M2", 15, 15, sources=[
                SourceStatus("shodan", "core", 0.35, "failed", "timeout"),
                SourceStatus("abuseipdb", "core", 0.35, "success"),
                SourceStatus("greynoise", "auxiliary", 0.15, "success"),
                SourceStatus("ip_api", "auxiliary", 0.15, "success"),
            ]),
        ]
        findings = Findings(domain="x", timestamp="t", modules=modules)
        score = ScoringEngine().calculate(findings)
        coverage_explanations = [
            e for e in score.explanations if "部分來源未回應" in e.reason
        ]
        assert len(coverage_explanations) == 1
        assert coverage_explanations[0].deduction == 0
        assert "shodan" in coverage_explanations[0].reason

    def test_score_json_includes_confidence(self):
        """save_score 產出的 JSON 應包含 confidence + source_coverage。"""
        score = Score(
            total=78, grade="B",
            dimensions={"M1": 18},
            explanations=[],
            confidence=0.92,
            source_coverage={"M1": 0.6, "M2": 1.0},
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            save_score(score, tmpdir)
            with open(os.path.join(tmpdir, "score.json")) as f:
                data = json.load(f)
        assert data["confidence"] == 0.92
        assert data["source_coverage"] == {"M1": 0.6, "M2": 1.0}
