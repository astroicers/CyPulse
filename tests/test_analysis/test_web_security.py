from cypulse.analysis.web_security import WebSecurityModule
from cypulse.models import Asset, Assets


class TestWebSecurityModule:
    def test_module_info(self):
        m = WebSecurityModule()
        assert m.module_id() == "M1"
        assert m.weight() == 0.25
        assert m.max_score() == 25

    def test_missing_headers(self):
        assets = Assets(
            domain="example.com",
            timestamp="test",
            subdomains=[
                Asset(subdomain="www.example.com", http_status=200, security_headers={}),
            ],
        )
        m = WebSecurityModule()
        result = m.run(assets)
        header_findings = [f for f in result.findings if f.severity != "info"]
        assert len(header_findings) == 3
        # Each finding should mention "1 個子網域"
        for f in header_findings:
            assert "1 個子網域" in f.description
        # Score: 25 - 3×min(1,5) = 25-3 = 22
        assert result.score == 22

    def test_all_headers_present(self):
        assets = Assets(
            domain="example.com",
            timestamp="test",
            subdomains=[
                Asset(
                    subdomain="www.example.com",
                    http_status=200,
                    security_headers={
                        "strict-transport-security": "max-age=31536000",
                        "content-security-policy": "default-src 'self'",
                        "x-frame-options": "DENY",
                    },
                ),
            ],
        )
        m = WebSecurityModule()
        result = m.run(assets)
        assert result.score == 25

    def test_no_http_assets(self):
        assets = Assets(domain="example.com", timestamp="test", subdomains=[])
        m = WebSecurityModule()
        result = m.run(assets)
        assert result.score == 25
        # May have info finding about nuclei not installed
        real_findings = [f for f in result.findings if f.severity != "info"]
        assert len(real_findings) == 0

    def test_many_subdomains_findings_capped(self):
        """多個子網域缺同一 header 時，每種 header 只產生一筆 finding。"""
        subs = [
            Asset(subdomain=f"sub{i}.example.com", http_status=200, security_headers={})
            for i in range(10)
        ]
        assets = Assets(domain="example.com", timestamp="test", subdomains=subs)
        m = WebSecurityModule()
        result = m.run(assets)
        header_findings = [f for f in result.findings if f.severity != "info"]
        assert len(header_findings) == 3  # not 30
        for f in header_findings:
            assert "10" in f.description

    def test_partial_headers_present(self):
        """部分子網域有設 header，只統計缺失的。"""
        assets = Assets(
            domain="example.com",
            timestamp="test",
            subdomains=[
                Asset(
                    subdomain="good.example.com",
                    http_status=200,
                    security_headers={
                        "strict-transport-security": "max-age=31536000",
                        "content-security-policy": "default-src 'self'",
                        "x-frame-options": "DENY",
                    },
                ),
                Asset(
                    subdomain="bad.example.com",
                    http_status=200,
                    security_headers={},
                ),
            ],
        )
        m = WebSecurityModule()
        result = m.run(assets)
        header_findings = [f for f in result.findings if f.severity != "info"]
        assert len(header_findings) == 3
        for f in header_findings:
            assert "bad.example.com" in f.description
            assert "good.example.com" not in f.description

    def test_score_deduction_per_header_capped(self):
        """每種 header 扣分有上限（最多 5 分/header）。"""
        subs = [
            Asset(subdomain=f"sub{i}.example.com", http_status=200, security_headers={})
            for i in range(20)
        ]
        assets = Assets(domain="example.com", timestamp="test", subdomains=subs)
        m = WebSecurityModule()
        result = m.run(assets)
        # 3 headers × 5 分上限 = 最多扣 15 分 → score >= 10
        assert result.score >= 10
