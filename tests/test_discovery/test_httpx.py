from unittest.mock import patch, MagicMock
from cypulse.discovery.httpx_tool import HttpxTool


class TestHttpxTool:
    def test_name(self):
        tool = HttpxTool()
        assert tool.name() == "httpx"

    @patch("cypulse.discovery.httpx_tool.check_tool", return_value=False)
    def test_tool_not_found(self, mock_check):
        tool = HttpxTool()
        result = tool.run("example.com", {})
        assert result == []

    @patch("subprocess.run")
    @patch("cypulse.discovery.httpx_tool.check_tool", return_value=True)
    def test_json_output(self, mock_check, mock_run):
        mock_run.return_value = MagicMock(
            stdout='{"url":"https://www.example.com","status_code":200,"title":"Example","input":"www.example.com","tls":{"version":"TLSv1.3"}}\n'
        )
        tool = HttpxTool()
        result = tool.run("www.example.com", {})
        assert len(result) == 1
        assert result[0]["http_status"] == 200
        assert result[0]["tls_version"] == "TLSv1.3"

    @patch("subprocess.run")
    @patch("cypulse.discovery.httpx_tool.check_tool", return_value=True)
    def test_parses_security_headers(self, mock_check, mock_run):
        import json
        httpx_json = json.dumps({
            "url": "https://www.example.com",
            "status_code": 200,
            "title": "Example",
            "input": "www.example.com",
            "header": {
                "strict_transport_security": "max-age=31536000",
                "content_security_policy": "default-src 'self'",
                "x_frame_options": "DENY",
                "server": "nginx",
            },
        })
        mock_run.return_value = MagicMock(stdout=httpx_json + "\n")
        tool = HttpxTool()
        result = tool.run("www.example.com", {})
        assert len(result) == 1
        headers = result[0]["security_headers"]
        assert headers["strict-transport-security"] == "max-age=31536000"
        assert headers["content-security-policy"] == "default-src 'self'"
        assert headers["x-frame-options"] == "DENY"
        # non-security headers should NOT be included
        assert "server" not in headers

    @patch("subprocess.run")
    @patch("cypulse.discovery.httpx_tool.check_tool", return_value=True)
    def test_no_header_field_returns_empty(self, mock_check, mock_run):
        import json
        httpx_json = json.dumps({
            "url": "https://www.example.com",
            "status_code": 200,
            "title": "Example",
            "input": "www.example.com",
        })
        mock_run.return_value = MagicMock(stdout=httpx_json + "\n")
        tool = HttpxTool()
        result = tool.run("www.example.com", {})
        assert result[0]["security_headers"] == {}
