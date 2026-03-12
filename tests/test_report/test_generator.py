import os
import tempfile
from cypulse.report.generator import ReportGenerator
from cypulse.models import Score, ScoreExplanation, Findings, ModuleResult, Finding, Assets, Asset


class TestReportGenerator:
    def _make_test_data(self):
        assets = Assets(
            domain="example.com",
            timestamp="2026-03-12T020000",
            subdomains=[
                Asset(subdomain="www.example.com", ip="93.184.216.34",
                      ports=[80, 443], http_status=200, http_title="Example"),
            ],
        )
        findings = Findings(
            domain="example.com",
            timestamp="2026-03-12T020000",
            modules=[
                ModuleResult(
                    module_id="M1", module_name="網站服務安全",
                    score=20, max_score=25,
                    findings=[
                        Finding(severity="medium", title="Missing HSTS",
                                description="缺少 HSTS header", score_impact=5),
                    ],
                    execution_time=5.0,
                ),
            ],
        )
        score = Score(
            total=78, grade="C",
            dimensions={"M1": 20},
            explanations=[ScoreExplanation(module_id="M1", reason="Missing HSTS", deduction=5)],
            scan_duration=120.0,
        )
        return assets, findings, score

    def test_generate_html(self):
        assets, findings, score = self._make_test_data()
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator()
            path = gen.generate_html(score, findings, assets, tmpdir)
            assert os.path.isfile(path)
            with open(path, encoding="utf-8") as f:
                html = f.read()
            assert "example.com" in html
            assert "78" in html
            assert "Missing HSTS" in html
            assert "CyPulse" in html

    def test_generate_csv(self):
        assets, findings, score = self._make_test_data()
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator()
            paths = gen.generate_csv(findings, assets, tmpdir)
            assert len(paths) == 2
            for p in paths:
                assert os.path.isfile(p)
            # Check assets CSV content
            with open(paths[0]) as f:
                content = f.read()
            assert "www.example.com" in content
