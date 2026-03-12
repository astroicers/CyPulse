from unittest.mock import patch, MagicMock
from cypulse.discovery.naabu import NaabuTool


class TestNaabuTool:
    def test_name(self):
        tool = NaabuTool()
        assert tool.name() == "naabu"

    @patch("cypulse.discovery.naabu.check_tool", return_value=False)
    def test_tool_not_found(self, mock_check):
        tool = NaabuTool()
        result = tool.run("example.com", {})
        assert result == []

    @patch("subprocess.run")
    @patch("cypulse.discovery.naabu.check_tool", return_value=True)
    def test_json_output(self, mock_check, mock_run):
        mock_run.return_value = MagicMock(
            stdout='{"host":"93.184.216.34","port":80}\n{"host":"93.184.216.34","port":443}\n'
        )
        tool = NaabuTool()
        result = tool.run("93.184.216.34", {})
        assert len(result) == 2
        assert result[0]["port"] == 80
