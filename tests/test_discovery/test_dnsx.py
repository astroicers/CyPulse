from unittest.mock import patch, MagicMock
from cypulse.discovery.dnsx import DnsxTool, resolve_subdomains


class TestDnsxTool:
    def test_name(self):
        tool = DnsxTool()
        assert tool.name() == "dnsx"

    @patch("cypulse.discovery.dnsx.check_tool", return_value=False)
    def test_tool_not_found(self, mock_check):
        tool = DnsxTool()
        result = tool.run("example.com", {})
        assert result == []

    @patch("subprocess.run")
    @patch("cypulse.discovery.dnsx.check_tool", return_value=True)
    def test_json_output(self, mock_check, mock_run):
        mock_run.return_value = MagicMock(
            stdout='{"host":"www.example.com","a":["93.184.216.34"]}\n'
        )
        tool = DnsxTool()
        result = tool.run("www.example.com", {})
        assert len(result) == 1
        assert result[0]["ip"] == "93.184.216.34"
