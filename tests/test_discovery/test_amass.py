from unittest.mock import patch, MagicMock
from cypulse.discovery.amass import AmassTool


class TestAmassTool:
    def test_name(self):
        tool = AmassTool()
        assert tool.name() == "amass"

    @patch("cypulse.discovery.amass.check_tool", return_value=False)
    def test_tool_not_found(self, mock_check):
        tool = AmassTool()
        result = tool.run("example.com", {})
        assert result == []

    @patch("cypulse.discovery.amass.run_cmd")
    @patch("cypulse.discovery.amass.check_tool", return_value=True)
    def test_json_output(self, mock_check, mock_run):
        mock_run.return_value = MagicMock(
            stdout='{"name":"www.example.com"}\n{"name":"mail.example.com"}\n'
        )
        tool = AmassTool()
        result = tool.run("example.com", {})
        assert len(result) == 2
        assert result[0]["subdomain"] == "www.example.com"
