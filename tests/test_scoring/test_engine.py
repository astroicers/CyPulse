import os
import json
import tempfile
from cypulse.scoring.engine import ScoringEngine, save_score
from cypulse.scoring.weights import get_grade
from cypulse.models import Findings, ModuleResult, Finding, Score


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
        assert get_grade(75) == "C"
        assert get_grade(70) == "C"
        assert get_grade(79) == "C"

    def test_grade_d(self):
        assert get_grade(60) == "D"
        assert get_grade(0) == "D"
        assert get_grade(69) == "D"


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
        assert score.grade == "C"
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
