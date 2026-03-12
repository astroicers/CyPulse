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
        assert result.module_id == "M1"
        # Missing 3 critical headers = -9
        assert result.score <= 25
        assert len(result.findings) >= 3

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
        assert len(result.findings) == 0
