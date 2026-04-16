from __future__ import annotations
import os
from unittest.mock import MagicMock, patch

from cypulse.analysis.ip_reputation import IPReputationModule
from cypulse.models import Asset, Assets


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

def _mock_shodan_response(
    vulns: list[str] | None = None, ports: list[int] | None = None
) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "cpes": [],
        "hostnames": [],
        "ip": "93.184.216.34",
        "ports": ports or [],
        "tags": [],
        "vulns": vulns or [],
    }
    return mock_resp


def _mock_greynoise_response(
    classification: str = "unknown",
    noise: bool = False,
    riot: bool = False,
    name: str = "N/A",
) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "ip": "93.184.216.34",
        "noise": noise,
        "riot": riot,
        "classification": classification,
        "name": name,
        "link": "https://viz.greynoise.io/ip/93.184.216.34",
        "last_seen": "2026-03-13",
        "message": "Success",
    }
    return mock_resp


def _mock_abuseipdb_response(abuse_score: int = 0, total_reports: int = 0) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "abuseConfidenceScore": abuse_score,
            "totalReports": total_reports,
        }
    }
    return mock_resp


def _mock_ipapi_response(
    status="success",
    country="US",
    org="AS9924 Taiwan Fixed Network",
    asn="AS9924",
    isp="Taiwan Fixed Network",
) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": status,
        "country": country,
        "org": org,
        "as": asn,
        "isp": isp,
    }
    return mock_resp


def _route_requests(shodan_resp=None, greynoise_resp=None, abuseipdb_resp=None, ipapi_resp=None):
    """回傳一個 side_effect function，根據 URL 分派對應的 mock response。"""
    def side_effect(*args, **kwargs):
        url = args[0] if args else kwargs.get("url", "")
        if "internetdb.shodan.io" in url:
            if shodan_resp is None:
                raise Exception("shodan down")
            return shodan_resp
        elif "greynoise.io" in url:
            if greynoise_resp is None:
                raise Exception("greynoise down")
            return greynoise_resp
        elif "abuseipdb.com" in url:
            if abuseipdb_resp is None:
                raise Exception("abuseipdb down")
            return abuseipdb_resp
        elif "ip-api.com" in url:
            if ipapi_resp is None:
                m = MagicMock()
                m.status_code = 200
                m.json.return_value = {
                    "status": "success",
                    "country": "US",
                    "org": "AS9924 Normal ISP",
                    "as": "AS9924",
                    "isp": "Normal ISP",
                }
                return m
            return ipapi_resp
        raise Exception(f"unexpected URL: {url}")
    return side_effect


class TestIPReputationModule:
    # ------------------------------------------------------------------
    # 模組基本資訊
    # ------------------------------------------------------------------

    def test_module_info(self):
        m = IPReputationModule()
        assert m.module_id() == "M2"
        assert m.module_name() == "IP 信譽"
        assert m.weight() == 0.15
        assert m.max_score() == 15

    # ------------------------------------------------------------------
    # 無 API Key — 仍可透過 Shodan + GreyNoise 執行
    # ------------------------------------------------------------------

    def test_no_api_key_still_runs(self, sample_assets):
        """未設定 ABUSEIPDB_API_KEY 時，仍透過免費來源執行，status=success。"""
        m = IPReputationModule()
        shodan_resp = _mock_shodan_response()
        greynoise_resp = _mock_greynoise_response()

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ABUSEIPDB_API_KEY", None)
            with patch("requests.get", side_effect=_route_requests(shodan_resp, greynoise_resp)):
                result = m.run(sample_assets)

        assert result.status == "success"
        assert result.score == m.max_score()

    # ------------------------------------------------------------------
    # Shodan InternetDB — 弱點偵測
    # ------------------------------------------------------------------

    def test_shodan_vulns_high(self, sample_assets):
        """Shodan 回報 >5 個 CVE 時，severity=high。"""
        m = IPReputationModule()
        vulns = [f"CVE-2024-{i}" for i in range(8)]
        shodan_resp = _mock_shodan_response(vulns=vulns)
        greynoise_resp = _mock_greynoise_response()

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ABUSEIPDB_API_KEY", None)
            with patch("requests.get", side_effect=_route_requests(shodan_resp, greynoise_resp)):
                result = m.run(sample_assets)

        shodan_findings = [f for f in result.findings if "弱點" in f.title]
        assert len(shodan_findings) == 1
        assert shodan_findings[0].severity == "high"
        assert shodan_findings[0].score_impact == 5  # min(5, 8)

    def test_shodan_vulns_medium(self, sample_assets):
        """Shodan 回報 1-5 個 CVE 時，severity=medium。"""
        m = IPReputationModule()
        vulns = ["CVE-2024-1234", "CVE-2024-5678"]
        shodan_resp = _mock_shodan_response(vulns=vulns)
        greynoise_resp = _mock_greynoise_response()

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ABUSEIPDB_API_KEY", None)
            with patch("requests.get", side_effect=_route_requests(shodan_resp, greynoise_resp)):
                result = m.run(sample_assets)

        shodan_findings = [f for f in result.findings if "弱點" in f.title]
        assert len(shodan_findings) == 1
        assert shodan_findings[0].severity == "medium"
        assert shodan_findings[0].score_impact == 2

    def test_shodan_no_vulns(self, sample_assets):
        """Shodan 無弱點時，不產生 finding。"""
        m = IPReputationModule()
        shodan_resp = _mock_shodan_response(vulns=[])
        greynoise_resp = _mock_greynoise_response()

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ABUSEIPDB_API_KEY", None)
            with patch("requests.get", side_effect=_route_requests(shodan_resp, greynoise_resp)):
                result = m.run(sample_assets)

        shodan_findings = [f for f in result.findings if "弱點" in f.title]
        assert len(shodan_findings) == 0

    def test_shodan_error_independent(self, sample_assets):
        """Shodan 失敗時，不影響 GreyNoise。"""
        m = IPReputationModule()
        greynoise_resp = _mock_greynoise_response(classification="malicious", name="Botnet")

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ABUSEIPDB_API_KEY", None)
            with patch("requests.get", side_effect=_route_requests(None, greynoise_resp)):
                result = m.run(sample_assets)

        assert result.status == "success"
        gn_findings = [f for f in result.findings if "GreyNoise" in f.title]
        assert len(gn_findings) == 1

    # ------------------------------------------------------------------
    # GreyNoise Community — IP 分類
    # ------------------------------------------------------------------

    def test_greynoise_malicious(self, sample_assets):
        """GreyNoise 分類為 malicious 時，severity=high，score_impact=5。"""
        m = IPReputationModule()
        shodan_resp = _mock_shodan_response()
        greynoise_resp = _mock_greynoise_response(classification="malicious", name="Mirai Botnet")

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ABUSEIPDB_API_KEY", None)
            with patch("requests.get", side_effect=_route_requests(shodan_resp, greynoise_resp)):
                result = m.run(sample_assets)

        gn_findings = [f for f in result.findings if "GreyNoise" in f.title]
        assert len(gn_findings) == 1
        assert gn_findings[0].severity == "high"
        assert gn_findings[0].score_impact == 5

    def test_greynoise_noise(self, sample_assets):
        """GreyNoise 偵測到掃描行為（noise=True）時，severity=medium，score_impact=2。"""
        m = IPReputationModule()
        shodan_resp = _mock_shodan_response()
        greynoise_resp = _mock_greynoise_response(noise=True, name="Scanner")

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ABUSEIPDB_API_KEY", None)
            with patch("requests.get", side_effect=_route_requests(shodan_resp, greynoise_resp)):
                result = m.run(sample_assets)

        gn_findings = [f for f in result.findings if "掃描" in f.title]
        assert len(gn_findings) == 1
        assert gn_findings[0].severity == "medium"
        assert gn_findings[0].score_impact == 2

    def test_greynoise_benign(self, sample_assets):
        """GreyNoise 分類為 benign 時，不產生 finding。"""
        m = IPReputationModule()
        shodan_resp = _mock_shodan_response()
        greynoise_resp = _mock_greynoise_response(classification="benign", name="Google DNS")

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ABUSEIPDB_API_KEY", None)
            with patch("requests.get", side_effect=_route_requests(shodan_resp, greynoise_resp)):
                result = m.run(sample_assets)

        gn_findings = [f for f in result.findings if "GreyNoise" in f.title or "掃描" in f.title]
        assert len(gn_findings) == 0

    def test_greynoise_error_independent(self, sample_assets):
        """GreyNoise 失敗時，不影響 Shodan。"""
        m = IPReputationModule()
        vulns = ["CVE-2024-1234"]
        shodan_resp = _mock_shodan_response(vulns=vulns)

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ABUSEIPDB_API_KEY", None)
            with patch("requests.get", side_effect=_route_requests(shodan_resp, None)):
                result = m.run(sample_assets)

        assert result.status == "success"
        shodan_findings = [f for f in result.findings if "弱點" in f.title]
        assert len(shodan_findings) == 1

    # ------------------------------------------------------------------
    # AbuseIPDB — 選填加值（有 key 才用）
    # ------------------------------------------------------------------

    def test_abuseipdb_high_abuse_score(self, sample_assets):
        """有 API key 且 abuseConfidenceScore > 50 時，產生 high finding。"""
        m = IPReputationModule()
        shodan_resp = _mock_shodan_response()
        greynoise_resp = _mock_greynoise_response()
        abuseipdb_resp = _mock_abuseipdb_response(abuse_score=85, total_reports=42)

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch(
                "requests.get",
                side_effect=_route_requests(shodan_resp, greynoise_resp, abuseipdb_resp),
            ):
                result = m.run(sample_assets)

        abuse_findings = [f for f in result.findings if "AbuseIPDB" in f.title]
        assert len(abuse_findings) == 1
        assert abuse_findings[0].severity == "high"
        assert abuse_findings[0].score_impact == 10

    def test_abuseipdb_medium_abuse_score(self, sample_assets):
        """有 API key 且 20 < abuseConfidenceScore <= 50 時，產生 medium finding。"""
        m = IPReputationModule()
        shodan_resp = _mock_shodan_response()
        greynoise_resp = _mock_greynoise_response()
        abuseipdb_resp = _mock_abuseipdb_response(abuse_score=35, total_reports=5)

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch(
                "requests.get",
                side_effect=_route_requests(shodan_resp, greynoise_resp, abuseipdb_resp),
            ):
                result = m.run(sample_assets)

        abuse_findings = [f for f in result.findings if "abuse reports" in f.title]
        assert len(abuse_findings) == 1
        assert abuse_findings[0].severity == "medium"
        assert abuse_findings[0].score_impact == 5

    def test_abuseipdb_clean_ip(self, sample_assets):
        """有 API key 且 abuseConfidenceScore <= 20 時，不產生 finding。"""
        m = IPReputationModule()
        shodan_resp = _mock_shodan_response()
        greynoise_resp = _mock_greynoise_response()
        abuseipdb_resp = _mock_abuseipdb_response(abuse_score=0)

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch(
                "requests.get",
                side_effect=_route_requests(shodan_resp, greynoise_resp, abuseipdb_resp),
            ):
                result = m.run(sample_assets)

        assert result.score == m.max_score()
        assert len(result.findings) == 0

    # ------------------------------------------------------------------
    # 無 IP 資產
    # ------------------------------------------------------------------

    def test_no_ips(self):
        """subdomains 中無任何 IP 時，score=max_score。"""
        assets = Assets(
            domain="example.com",
            timestamp="test",
            subdomains=[Asset(subdomain="www.example.com")],
        )
        m = IPReputationModule()

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ABUSEIPDB_API_KEY", None)
            with patch("requests.get") as mock_get:
                result = m.run(assets)
                mock_get.assert_not_called()

        assert result.status == "success"
        assert result.score == m.max_score()

    def test_empty_subdomains(self):
        """subdomains 完全為空時，score=max_score。"""
        assets = Assets(domain="example.com", timestamp="test", subdomains=[])
        m = IPReputationModule()

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ABUSEIPDB_API_KEY", None)
            with patch("requests.get") as mock_get:
                result = m.run(assets)
                mock_get.assert_not_called()

        assert result.status == "success"
        assert result.score == m.max_score()

    # ------------------------------------------------------------------
    # 全部 API 失敗
    # ------------------------------------------------------------------

    def test_all_apis_fail(self, sample_assets):
        """所有 API 都失敗時，score=max_score，不崩潰。"""
        m = IPReputationModule()

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ABUSEIPDB_API_KEY", None)
            with patch("requests.get", side_effect=Exception("network down")):
                result = m.run(sample_assets)

        assert result.status == "success"
        assert result.score == m.max_score()
        assert result.findings == []

    # ------------------------------------------------------------------
    # score 不得低於 0
    # ------------------------------------------------------------------

    def test_score_floor_at_zero(self):
        """多個高風險 IP 累積扣分時，score 不應低於 0。"""
        assets = Assets(
            domain="example.com",
            timestamp="test",
            subdomains=[
                Asset(subdomain="a.example.com", ip="1.1.1.1"),
                Asset(subdomain="b.example.com", ip="2.2.2.2"),
            ],
        )
        m = IPReputationModule()
        vulns = [f"CVE-2024-{i}" for i in range(10)]
        shodan_resp = _mock_shodan_response(vulns=vulns)
        greynoise_resp = _mock_greynoise_response(classification="malicious", name="Botnet")

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ABUSEIPDB_API_KEY", None)
            with patch("requests.get", side_effect=_route_requests(shodan_resp, greynoise_resp)):
                result = m.run(assets)

        assert result.score >= 0

    # ------------------------------------------------------------------
    # 三來源組合
    # ------------------------------------------------------------------

    def test_all_three_sources(self, sample_assets):
        """三來源同時有結果時，findings 合併，分數正確扣減。"""
        m = IPReputationModule()
        shodan_resp = _mock_shodan_response(vulns=["CVE-2024-1234", "CVE-2024-5678"])
        greynoise_resp = _mock_greynoise_response(classification="malicious", name="Botnet")
        abuseipdb_resp = _mock_abuseipdb_response(abuse_score=85, total_reports=42)

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch(
                "requests.get",
                side_effect=_route_requests(shodan_resp, greynoise_resp, abuseipdb_resp),
            ):
                result = m.run(sample_assets)

        assert len(result.findings) == 3
        # Shodan: 2 vulns → impact=2, GreyNoise: malicious → impact=5, AbuseIPDB: high → impact=10
        # 15 - 2 - 5 - 10 = -2 → floor at 0
        assert result.score == 0

    # ------------------------------------------------------------------
    # 內部方法單元測試
    # ------------------------------------------------------------------

    def test_check_shodan_internetdb_returns_findings(self):
        """_check_shodan_internetdb 有 CVE 時回傳 findings。"""
        m = IPReputationModule()
        mock_resp = _mock_shodan_response(vulns=["CVE-2024-1234"])

        with patch("requests.get", return_value=mock_resp):
            findings = m._check_shodan_internetdb("1.2.3.4")

        assert len(findings) == 1
        assert "CVE-2024-1234" in findings[0].evidence

    def test_check_shodan_internetdb_empty_on_error(self):
        """_check_shodan_internetdb 失敗時回傳空清單。"""
        m = IPReputationModule()

        with patch("requests.get", side_effect=RuntimeError("fail")):
            findings = m._check_shodan_internetdb("1.2.3.4")

        assert findings == []

    def test_check_greynoise_returns_finding_on_malicious(self):
        """_check_greynoise malicious 時回傳 finding。"""
        m = IPReputationModule()
        mock_resp = _mock_greynoise_response(classification="malicious", name="Botnet")

        with patch("requests.get", return_value=mock_resp):
            finding = m._check_greynoise("1.2.3.4")

        assert finding is not None
        assert finding.severity == "high"

    def test_check_greynoise_returns_none_on_error(self):
        """_check_greynoise 失敗時回傳 None。"""
        m = IPReputationModule()

        with patch("requests.get", side_effect=RuntimeError("fail")):
            finding = m._check_greynoise("1.2.3.4")

        assert finding is None

    # ------------------------------------------------------------------
    # 去重：同 IP 同來源不重複計分
    # ------------------------------------------------------------------

    def test_each_source_counted_once_per_ip(self):
        """同一 IP 每個來源最多只產生一筆 finding，不重複計分。"""
        assets = Assets(
            domain="example.com",
            timestamp="test",
            subdomains=[Asset(subdomain="www.example.com", ip="1.2.3.4")],
        )
        m = IPReputationModule()
        # Shodan 有弱點（impact=2），GreyNoise 惡意（impact=5）
        shodan_resp = _mock_shodan_response(vulns=["CVE-2024-1234", "CVE-2024-5678"])
        greynoise_resp = _mock_greynoise_response(classification="malicious", name="Botnet")

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ABUSEIPDB_API_KEY", None)
            with patch("requests.get", side_effect=_route_requests(shodan_resp, greynoise_resp)):
                result = m.run(assets)

        # 每個來源只計一次：Shodan 1 筆 + GreyNoise 1 筆 = 2 筆
        assert len(result.findings) == 2
        # 分數：15 - 2（shodan）- 5（greynoise）= 8
        assert result.score == 8

    def test_multiple_ips_each_deduped_independently(self):
        """多個 IP 各自獨立去重，不互相影響。"""
        assets = Assets(
            domain="example.com",
            timestamp="test",
            subdomains=[
                Asset(subdomain="a.example.com", ip="1.1.1.1"),
                Asset(subdomain="b.example.com", ip="2.2.2.2"),
            ],
        )
        m = IPReputationModule()
        # 兩個 IP 都只有 GreyNoise 噪音（impact=2 each）
        shodan_resp = _mock_shodan_response(vulns=[])
        greynoise_resp = _mock_greynoise_response(noise=True, name="Scanner")

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ABUSEIPDB_API_KEY", None)
            with patch("requests.get", side_effect=_route_requests(shodan_resp, greynoise_resp)):
                result = m.run(assets)

        # 2 個 IP × 1 greynoise finding 各 = 2 筆
        gn_findings = [f for f in result.findings if "掃描" in f.title]
        assert len(gn_findings) == 2
        # 15 - 2 - 2 = 11
        assert result.score == 11


class TestIPAPI:
    def test_ipapi_tor_exit_node(self, sample_assets):
        """IP-API 回傳已知 Tor/VPN org 時，應產生 medium severity finding。"""
        ipapi_resp = _mock_ipapi_response(
            org="AS60729 Tor Project Inc",
            asn="AS60729",
            isp="Tor Project",
        )

        def side_effect(url, **kwargs):
            if "ip-api.com" in url:
                return ipapi_resp
            m = MagicMock()
            m.status_code = 200
            m.json.return_value = {}
            return m

        m = IPReputationModule()
        sample_assets.subdomains[0].ip = "185.220.101.1"
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ABUSEIPDB_API_KEY", None)
            with patch("requests.get", side_effect=side_effect):
                result = m.run(sample_assets)

        ipapi_findings = [
            f for f in result.findings
            if "ASN" in f.title or "Tor" in f.title or "VPN" in (f.description or "")
        ]
        assert len(ipapi_findings) >= 1

    def test_ipapi_normal_ip_no_finding(self, sample_assets):
        """IP-API 回傳正常 IP（非 VPN/Tor）時，不應產生 finding。"""
        ipapi_resp = _mock_ipapi_response(
            country="TW",
            org="AS9924 Taiwan Fixed Network",
            asn="AS9924",
            isp="Taiwan Fixed Network",
        )

        def side_effect(url, **kwargs):
            if "ip-api.com" in url:
                return ipapi_resp
            m = MagicMock()
            m.status_code = 200
            m.json.return_value = {}
            return m

        m = IPReputationModule()
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ABUSEIPDB_API_KEY", None)
            with patch("requests.get", side_effect=side_effect):
                result = m.run(sample_assets)

        ipapi_findings = [
            f for f in result.findings
            if "ipapi" in f.title.lower() or "ASN" in f.title
        ]
        assert len(ipapi_findings) == 0
