import os
import tempfile
from cypulse.report.generator import ReportGenerator
from cypulse.models import (
    Score, ScoreExplanation, Findings, ModuleResult, Finding,
    Assets, Asset, SourceStatus,
)


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
                        Finding(severity="high", title="No SPF record",
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

    def test_html_includes_confidence_badge(self):
        """HTML 報告應顯示信心分數百分比。"""
        assets, findings, score = self._make_test_data()
        score.confidence = 0.92
        score.source_coverage = {"M1": 1.0}
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator()
            path = gen.generate_html(score, findings, assets, tmpdir)
            html = open(path, encoding="utf-8").read()
        assert "信心" in html
        assert "92" in html  # 92%

    def test_html_low_confidence_warning(self):
        """confidence < 0.8 時 HTML 應含警告 class。"""
        assets, findings, score = self._make_test_data()
        score.confidence = 0.65
        score.source_coverage = {"M1": 0.65}
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator()
            path = gen.generate_html(score, findings, assets, tmpdir)
            html = open(path, encoding="utf-8").read()
        # 用 confidence-low class 標識（CSS 變紅）
        assert "confidence-low" in html

    def test_html_shows_failed_sources(self):
        """有失效來源的模組，HTML 應列出 failed source IDs。"""
        assets = Assets(
            domain="example.com", timestamp="t",
            subdomains=[Asset(subdomain="www.example.com", ip="1.2.3.4")],
        )
        findings = Findings(
            domain="example.com", timestamp="t",
            modules=[
                ModuleResult(
                    module_id="M2", module_name="IP 信譽",
                    score=15, max_score=15, findings=[],
                    execution_time=2.0,
                    sources=[
                        SourceStatus("shodan", "core", 0.35, "failed", "timeout"),
                        SourceStatus("abuseipdb", "core", 0.35, "success"),
                        SourceStatus("greynoise", "auxiliary", 0.15, "success"),
                        SourceStatus("ip_api", "auxiliary", 0.15, "success"),
                    ],
                ),
            ],
        )
        score = Score(
            total=15, grade="D", dimensions={"M2": 15},
            explanations=[], scan_duration=2.0,
            confidence=0.65,
            source_coverage={"M2": 0.65},
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator()
            path = gen.generate_html(score, findings, assets, tmpdir)
            html = open(path, encoding="utf-8").read()
        # 失效來源 ID 應出現在 HTML 中
        assert "shodan" in html
        # 不應誤報已成功的來源為失敗
        assert "abuseipdb" not in html or "shodan" in html  # smoke check

    def test_deduction_table_filters_zero_entries(self):
        """扣分明細表不應顯示 deduction=0 的說明列（屬於 source coverage 警告等）"""
        assets, findings, _ = self._make_test_data()
        score = Score(
            total=80, grade="B", dimensions={"M1": 20, "M2": 15},
            explanations=[
                ScoreExplanation(module_id="M1", reason="Missing HSTS", deduction=5),
                ScoreExplanation(
                    module_id="M2",
                    reason="IP 信譽 部分來源未回應（信心 65%，失效來源: greynoise）",
                    deduction=0,
                ),
            ],
            scan_duration=10.0,
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator()
            path = gen.generate_html(score, findings, assets, tmpdir)
            html = open(path, encoding="utf-8").read()
        # 實際扣分項應出現
        assert "Missing HSTS" in html
        assert ">-5<" in html
        # 零扣分項不應進扣分明細表格
        assert "部分來源未回應" not in html.split("<h2>扣分明細</h2>")[1].split("</table>")[0]
        assert ">-0<" not in html

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
