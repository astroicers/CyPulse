import json
import subprocess
from unittest.mock import patch, MagicMock
from cypulse.analysis.web_security import WebSecurityModule
from cypulse.models import Asset, Assets
import pytest


@pytest.fixture
def sample_assets():
    return Assets(
        domain="example.com",
        timestamp="test",
        subdomains=[
            Asset(subdomain="www.example.com", ip="93.184.216.34",
                  http_status=200, ports=[443]),
        ],
    )


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
            assert "10 個子網域" in f.description

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


class TestTestssl:
    def test_testssl_cert_expiry_warning(self, sample_assets):
        """testssl.sh 偵測到憑證即將過期時，應產生 high severity finding。"""
        testssl_output = json.dumps([
            {
                "id": "cert_expirationStatus",
                "severity": "HIGH",
                "finding": "certificate expires in 10 days",
                "ip": "93.184.216.34/443"
            }
        ])
        mock_result = MagicMock(spec=subprocess.CompletedProcess)
        mock_result.stdout = testssl_output
        mock_result.returncode = 0

        m = WebSecurityModule()
        with patch(
            "cypulse.analysis.web_security.check_tool",
            side_effect=lambda t: t == "testssl.sh",
        ), patch("cypulse.analysis.web_security.run_cmd", return_value=mock_result):
            result = m.run(sample_assets)

        testssl_findings = [
            f for f in result.findings
            if (
                "testssl" in f.title.lower()
                or "cert" in f.title.lower()
                or "certificate" in f.title.lower()
                or "tls issue" in f.title.lower()
            )
        ]
        assert len(testssl_findings) >= 1
        assert any(f.severity in ("high", "critical") for f in testssl_findings)

    def test_testssl_not_installed(self, sample_assets):
        """testssl.sh 未安裝時，status 仍為 partial，並附 info finding。"""
        m = WebSecurityModule()
        with patch("cypulse.analysis.web_security.check_tool", return_value=False):
            result = m.run(sample_assets)

        info_findings = [f for f in result.findings if f.severity == "info"]
        testssl_info = [f for f in info_findings if "testssl" in f.title.lower()]
        assert len(testssl_info) >= 1
        assert result.status == "partial"
