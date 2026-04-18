"""diagnostics.format_error 測試。

把常見 Exception 分類並回傳「修復建議」字串，幫助使用者自助排障。
"""
from __future__ import annotations

import subprocess

from cypulse.utils.diagnostics import format_error


class TestFormatError:

    def test_dnspython_too_old(self):
        """ImportError('No module named "dns.nameserver"') → 提示升級 dnspython。"""
        exc = ImportError("No module named 'dns.nameserver'")
        msg = format_error(exc)
        assert "dnspython" in msg.lower()
        assert "2.4" in msg or "upgrade" in msg.lower() or "升級" in msg

    def test_requests_timeout(self):
        """requests.Timeout → 提示重試 / 增加 --timeout。"""
        import requests
        exc = requests.Timeout("connection timed out")
        msg = format_error(exc)
        assert "timeout" in msg.lower() or "逾時" in msg or "無回應" in msg

    def test_subprocess_timeout(self):
        """subprocess.TimeoutExpired → 提示工具超時。"""
        exc = subprocess.TimeoutExpired(cmd="nuclei", timeout=300)
        msg = format_error(exc)
        assert "工具" in msg or "tool" in msg.lower() or "subprocess" in msg.lower()

    def test_file_not_found_for_tool(self):
        """FileNotFoundError 含工具名稱 → 提示安裝。"""
        exc = FileNotFoundError(2, "No such file or directory", "nuclei")
        msg = format_error(exc)
        assert "nuclei" in msg or "DEPLOY_SPEC" in msg or "安裝" in msg

    def test_generic_exception_fallback(self):
        """未分類 Exception → 至少回傳 type + str(exc)。"""
        exc = RuntimeError("something unexpected")
        msg = format_error(exc)
        assert "RuntimeError" in msg
        assert "something unexpected" in msg

    def test_diff_schema_error(self):
        """DiffSchemaError → 提示 schema 不相容 + 重新掃描。"""
        from cypulse.automation.diff import DiffSchemaError
        exc = DiffSchemaError("findings.json missing modules")
        msg = format_error(exc)
        assert "schema" in msg.lower() or "格式" in msg or "相容" in msg
