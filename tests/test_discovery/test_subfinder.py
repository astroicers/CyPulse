from unittest.mock import patch, MagicMock
from cypulse.discovery.subfinder import SubfinderTool


class TestSubfinderTool:
    def test_name(self):
        tool = SubfinderTool()
        assert tool.name() == "subfinder"

    @patch("cypulse.discovery.subfinder.check_tool", return_value=False)
    def test_tool_not_found(self, mock_check):
        tool = SubfinderTool()
        result = tool.run("example.com", {})
        assert result == []

    @patch("cypulse.discovery.subfinder.run_cmd")
    @patch("cypulse.discovery.subfinder.check_tool", return_value=True)
    def test_json_output(self, mock_check, mock_run):
        mock_run.return_value = MagicMock(
            stdout='{"host":"www.example.com","source":"subfinder"}\n{"host":"api.example.com","source":"subfinder"}\n'
        )
        tool = SubfinderTool()
        result = tool.run("example.com", {})
        assert len(result) == 2
        assert result[0]["subdomain"] == "www.example.com"

    @patch("cypulse.discovery.subfinder.run_cmd")
    @patch("cypulse.discovery.subfinder.check_tool", return_value=True)
    def test_plain_output(self, mock_check, mock_run):
        mock_run.return_value = MagicMock(stdout="www.example.com\napi.example.com\n")
        tool = SubfinderTool()
        result = tool.run("example.com", {})
        assert len(result) == 2

    @patch("cypulse.discovery.subfinder.run_cmd", side_effect=Exception("timeout"))
    @patch("cypulse.discovery.subfinder.check_tool", return_value=True)
    def test_error_handling(self, mock_check, mock_run):
        tool = SubfinderTool()
        result = tool.run("example.com", {})
        assert result == []
