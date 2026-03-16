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

    def test_report_includes_remediation_for_known_finding(self):
        """報告 HTML 中應包含已知 finding 的補救建議。"""
        assets = Assets(
            domain="example.com",
            timestamp="2026-03-12T020000",
            subdomains=[],
        )
        findings = Findings(
            domain="example.com",
            timestamp="2026-03-12T020000",
            modules=[
                ModuleResult(
                    module_id="M5", module_name="郵件安全",
                    score=8, max_score=10,
                    findings=[
                        Finding(severity="high", title="No SPF Record",
                                description="缺少 SPF 記錄", score_impact=2),
                    ],
                    execution_time=1.0,
                ),
            ],
        )
        score = Score(
            total=88, grade="B",
            dimensions={"M5": 8},
            explanations=[],
            scan_duration=10.0,
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator()
            path = gen.generate_html(score, findings, assets, tmpdir)
            with open(path, encoding="utf-8") as f:
                html = f.read()
        assert "補救建議" in html or "Remediation" in html
        assert "SPF" in html

    def test_report_no_remediation_for_unknown_finding(self):
        """未知 finding 不應顯示補救建議區塊。"""
        assets = Assets(
            domain="example.com",
            timestamp="2026-03-12T020000",
            subdomains=[],
        )
        findings = Findings(
            domain="example.com",
            timestamp="2026-03-12T020000",
            modules=[
                ModuleResult(
                    module_id="M1", module_name="網站服務安全",
                    score=20, max_score=25,
                    findings=[
                        Finding(severity="low", title="Unknown Issue XYZ",
                                description="未知問題", score_impact=5),
                    ],
                    execution_time=1.0,
                ),
            ],
        )
        score = Score(
            total=80, grade="B",
            dimensions={"M1": 20},
            explanations=[],
            scan_duration=10.0,
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator()
            path = gen.generate_html(score, findings, assets, tmpdir)
            with open(path, encoding="utf-8") as f:
                html = f.read()
        # Unknown finding 不應有實際的 remediation details element（CSS 定義除外）
        assert '<details class="remediation-block">' not in html

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
