from cypulse.models import Score, ScoreExplanation, DiffItem, DiffReport


class TestScore:
    def test_create_score(self):
        score = Score(
            total=78,
            grade="C",
            dimensions={"M1": 18, "M2": 15, "M3": 15, "M4": 12, "M5": 8, "M6": 7, "M7": 3},
            explanations=[
                ScoreExplanation(module_id="M1", reason="Missing HSTS", deduction=5),
            ],
            scan_duration=120.5,
        )
        assert score.total == 78
        assert score.grade == "C"
        assert len(score.explanations) == 1

    def test_to_dict(self):
        score = Score(total=90, grade="A")
        d = score.to_dict()
        assert d["total"] == 90
        assert d["grade"] == "A"


class TestDiffReport:
    def test_create_diff(self):
        diff = DiffReport(
            old_scan="2026-03-01T020000",
            new_scan="2026-03-08T020000",
            score_change=-5,
            new_findings=[DiffItem(category="new_finding", severity="high", description="New CVE found")],
            resolved_findings=[],
            alerts=["Score dropped by 5 points"],
        )
        assert diff.score_change == -5
        assert len(diff.new_findings) == 1
        assert len(diff.alerts) == 1
