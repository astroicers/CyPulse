import subprocess as stdlib_subprocess
import pytest
from unittest.mock import patch
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


    def test_retry_backoff_capped_at_max_backoff(self):
        """backoff 不應超過 max_backoff（預設 60s）。"""
        sleep_calls = []

        with patch("time.sleep", side_effect=lambda x: sleep_calls.append(x)), \
             patch("subprocess.run", side_effect=stdlib_subprocess.TimeoutExpired([], 1)):
            with pytest.raises(stdlib_subprocess.TimeoutExpired):
                run_cmd(["cmd"], timeout=1, max_retries=5, retry_delay=10.0, max_backoff=60.0)

        for delay in sleep_calls:
            assert delay <= 60.0, f"backoff {delay} exceeded max_backoff 60.0"

    def test_retry_backoff_grows_without_cap(self):
        """未設定 max_backoff 時，backoff 應正常指數增長（預設上限 60s）。"""
        sleep_calls = []

        with patch("time.sleep", side_effect=lambda x: sleep_calls.append(x)), \
             patch("subprocess.run", side_effect=stdlib_subprocess.TimeoutExpired([], 1)):
            with pytest.raises(stdlib_subprocess.TimeoutExpired):
                run_cmd(["cmd"], timeout=1, max_retries=3, retry_delay=1.0)

        # 預設 max_backoff=60，3 次：1.0, 2.0, 4.0 — 皆 ≤ 60
        assert len(sleep_calls) == 3
        assert sleep_calls == [1.0, 2.0, 4.0]


class TestCheckTool:
    def test_existing_tool(self):
        assert check_tool("echo") is True

    def test_nonexistent_tool(self):
        assert check_tool("nonexistent_tool_xyz") is False
