import pytest
from cypulse.utils.subprocess import run_cmd, check_tool


class TestRunCmd:
    def test_run_echo(self):
        result = run_cmd(["echo", "hello"])
        assert result.returncode == 0
        assert "hello" in result.stdout

    def test_run_failure(self):
        with pytest.raises(Exception):
            run_cmd(["false"])

    def test_run_no_check(self):
        result = run_cmd(["false"], check=False)
        assert result.returncode != 0


class TestCheckTool:
    def test_existing_tool(self):
        assert check_tool("echo") is True

    def test_nonexistent_tool(self):
        assert check_tool("nonexistent_tool_xyz") is False
