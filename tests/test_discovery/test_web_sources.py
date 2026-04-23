from unittest.mock import patch, MagicMock
from cypulse.discovery.web_sources import (
    query_crtsh,
    query_crtsh_certificates,
    query_hackertarget,
    query_subdomain_center,
    query_web_sources,
    _is_valid_subdomain,
)


def _mock_response(status_code=200, json_data=None, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    resp.text = text
    return resp


class TestIsValidSubdomain:
    def test_valid(self):
        assert _is_valid_subdomain("www.example.com", "example.com")

    def test_base_domain(self):
        assert _is_valid_subdomain("example.com", "example.com")

    def test_deep_subdomain(self):
        assert _is_valid_subdomain("a.b.c.example.com", "example.com")

    def test_empty(self):
        assert not _is_valid_subdomain("", "example.com")

    def test_too_long(self):
        assert not _is_valid_subdomain("a" * 254, "example.com")

    def test_wrong_domain(self):
        assert not _is_valid_subdomain("www.other.com", "example.com")

    def test_wildcard(self):
        assert not _is_valid_subdomain("*.example.com", "example.com")

    def test_invalid_chars(self):
        assert not _is_valid_subdomain("foo!bar.example.com", "example.com")
        assert not _is_valid_subdomain('foo"bar.example.com', "example.com")


class TestQueryCrtsh:
    @patch("cypulse.utils.http.requests.get")
    def test_parses_json(self, mock_get):
        mock_get.return_value = _mock_response(
            json_data=[
                {"name_value": "www.example.com\napi.example.com"},
                {"name_value": "*.example.com"},
                {"name_value": "mail.example.com"},
            ]
        )
        result = query_crtsh("example.com")
        assert "www.example.com" in result
        assert "api.example.com" in result
        assert "mail.example.com" in result
        # wildcard filtered
        assert "*.example.com" not in result

    @patch("cypulse.utils.http.requests.get")
    def test_non_200(self, mock_get):
        mock_get.return_value = _mock_response(status_code=503)
        assert query_crtsh("example.com") == []

    @patch("cypulse.utils.http.requests.get")
    def test_exception(self, mock_get):
        mock_get.side_effect = Exception("timeout")
        assert query_crtsh("example.com") == []

    @patch("cypulse.utils.http.requests.get")
    def test_html_fallback_when_json_502(self, mock_get):
        """JSON 回 502 時，應 fallback 到 HTML table 解析（模擬 crt.sh 後端半掛）。"""
        html_snippet = (
            "<html><body><TABLE>"
            '<TR>'
            '<TD><A href="?id=1234">1234</A></TD>'
            "<TD>2025-09-01</TD><TD>2025-09-01</TD><TD>2025-12-01</TD>"
            "<TD>example.com</TD>"
            "<TD>*.example.com<BR>example.com</TD>"
            "<TD>C=US, O=Let's Encrypt, CN=E1</TD>"
            "</TR>"
            "</TABLE></body></html>"
        )

        def side_effect(url, **kwargs):
            params = kwargs.get("params") or {}
            if params.get("output") == "json":
                return _mock_response(status_code=502, text="bad gateway")
            return _mock_response(status_code=200, text=html_snippet)

        mock_get.side_effect = side_effect
        certs = query_crtsh_certificates("example.com")
        assert len(certs) == 1
        assert certs[0]["crt_id"] == "1234"
        assert certs[0]["common_name"] == "example.com"
        assert "*.example.com" in certs[0]["sans"]
        assert "example.com" in certs[0]["sans"]
        assert "Let" in certs[0]["issuer"]


class TestQueryHackertarget:
    @patch("cypulse.utils.http.requests.get")
    def test_parses_csv(self, mock_get):
        mock_get.return_value = _mock_response(
            text="www.example.com,93.184.216.34\napi.example.com,93.184.216.35"
        )
        result = query_hackertarget("example.com")
        assert "www.example.com" in result
        assert "api.example.com" in result

    @patch("cypulse.utils.http.requests.get")
    def test_error_response(self, mock_get):
        mock_get.return_value = _mock_response(text="error check bread")
        assert query_hackertarget("example.com") == []

    @patch("cypulse.utils.http.requests.get")
    def test_empty(self, mock_get):
        mock_get.return_value = _mock_response(text="")
        assert query_hackertarget("example.com") == []

    @patch("cypulse.utils.http.requests.get")
    def test_exception(self, mock_get):
        mock_get.side_effect = Exception("connection error")
        assert query_hackertarget("example.com") == []


class TestQuerySubdomainCenter:
    @patch("cypulse.utils.http.requests.get")
    def test_parses_json(self, mock_get):
        mock_get.return_value = _mock_response(
            json_data=["www.example.com", "api.example.com", "db.example.com"]
        )
        result = query_subdomain_center("example.com")
        assert "www.example.com" in result
        assert "api.example.com" in result
        assert "db.example.com" in result

    @patch("cypulse.utils.http.requests.get")
    def test_filters_invalid(self, mock_get):
        mock_get.return_value = _mock_response(
            json_data=[
                "www.example.com",
                "foo!bar.example.com",
                'bad"name.example.com',
                "www.other.com",
            ]
        )
        result = query_subdomain_center("example.com")
        assert result == ["www.example.com"]

    @patch("cypulse.utils.http.requests.get")
    def test_non_list_response(self, mock_get):
        mock_get.return_value = _mock_response(json_data={"error": "rate limited"})
        assert query_subdomain_center("example.com") == []

    @patch("cypulse.utils.http.requests.get")
    def test_exception(self, mock_get):
        mock_get.side_effect = Exception("dns error")
        assert query_subdomain_center("example.com") == []


class TestQueryWebSources:
    @patch("cypulse.discovery.web_sources.query_subdomain_center")
    @patch("cypulse.discovery.web_sources.query_hackertarget")
    @patch("cypulse.discovery.web_sources.query_crtsh")
    def test_dedup_across_sources(self, mock_crt, mock_ht, mock_sc):
        mock_crt.return_value = ["www.example.com", "api.example.com"]
        mock_ht.return_value = ["www.example.com", "mail.example.com"]
        mock_sc.return_value = ["api.example.com", "db.example.com"]

        result = query_web_sources("example.com", {})
        subs = [r["subdomain"] for r in result]
        assert len(subs) == len(set(subs))
        assert set(subs) == {
            "www.example.com", "api.example.com", "mail.example.com", "db.example.com",
        }

    @patch("cypulse.discovery.web_sources.query_subdomain_center")
    @patch("cypulse.discovery.web_sources.query_hackertarget")
    @patch("cypulse.discovery.web_sources.query_crtsh")
    def test_source_failure_independent(self, mock_crt, mock_ht, mock_sc):
        mock_crt.side_effect = Exception("crtsh down")
        mock_ht.return_value = ["www.example.com"]
        mock_sc.return_value = ["api.example.com"]

        result = query_web_sources("example.com", {})
        subs = [r["subdomain"] for r in result]
        assert "www.example.com" in subs
        assert "api.example.com" in subs

    @patch("cypulse.discovery.web_sources.query_subdomain_center")
    @patch("cypulse.discovery.web_sources.query_hackertarget")
    @patch("cypulse.discovery.web_sources.query_crtsh")
    def test_all_sources_fail(self, mock_crt, mock_ht, mock_sc):
        mock_crt.side_effect = Exception("fail")
        mock_ht.side_effect = Exception("fail")
        mock_sc.side_effect = Exception("fail")

        result = query_web_sources("example.com", {})
        assert result == []

    @patch("cypulse.discovery.web_sources.query_subdomain_center")
    @patch("cypulse.discovery.web_sources.query_hackertarget")
    @patch("cypulse.discovery.web_sources.query_crtsh")
    def test_sorted_output(self, mock_crt, mock_ht, mock_sc):
        mock_crt.return_value = ["z.example.com"]
        mock_ht.return_value = ["a.example.com"]
        mock_sc.return_value = ["m.example.com"]

        result = query_web_sources("example.com", {})
        subs = [r["subdomain"] for r in result]
        assert subs == sorted(subs)
