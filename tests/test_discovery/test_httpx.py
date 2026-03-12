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
