from unittest.mock import patch, MagicMock
from cypulse.discovery.dnsx import DnsxTool


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

    @patch("subprocess.run")
    @patch("cypulse.discovery.dnsx.check_tool", return_value=True)
    def test_dnsx_complete_logs_resolved_and_total(self, mock_check, mock_run):
        """log 應區分總筆數（含 NXDOMAIN）與實際解析成功的數量"""
        stdout = (
            '{"host":"a.example.com","a":["1.1.1.1"]}\n'
            '{"host":"b.example.com","a":["2.2.2.2"]}\n'
            '{"host":"c.example.com","status_code":"NXDOMAIN"}\n'
        )
        mock_run.return_value = MagicMock(stdout=stdout)

        with patch("cypulse.discovery.dnsx.logger") as mock_logger:
            tool = DnsxTool()
            tool.run("ignored", {})

        complete_calls = [
            call for call in mock_logger.info.call_args_list
            if call.args and call.args[0] == "dnsx_complete"
        ]
        assert complete_calls, "expected dnsx_complete log call"
        kwargs = complete_calls[-1].kwargs
        assert kwargs.get("total") == 3
        assert kwargs.get("resolved") == 2
