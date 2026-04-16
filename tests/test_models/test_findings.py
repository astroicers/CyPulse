from cypulse.models import Finding, Findings


class TestFinding:
    def test_create_finding(self, sample_finding):
        assert sample_finding.severity == "high"
        assert sample_finding.score_impact == 5

    def test_finding_defaults(self):
        f = Finding(severity="info", title="Test", description="Desc")
        assert f.evidence is None
        assert f.score_impact == 0


class TestModuleResult:
    def test_create_module_result(self, sample_module_result):
        assert sample_module_result.module_id == "M1"
        assert sample_module_result.score == 20
        assert len(sample_module_result.findings) == 1

    def test_to_dict(self, sample_module_result):
        d = sample_module_result.to_dict()
        assert d["module_id"] == "M1"


class TestFindings:
    def test_create_findings(self, sample_module_result):
        f = Findings(
            domain="example.com",
            timestamp="2026-03-12T020000",
            modules=[sample_module_result],
        )
        assert len(f.modules) == 1
        d = f.to_dict()
        assert d["domain"] == "example.com"
