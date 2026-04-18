"""SIT-2: scan 兩次後 diff 自動觸發 + atomic write 韌性驗證。

驗證：
- 第二次 scan 自動偵測前次掃描並產生 diff.json
- atomic write 確保即使前次 scan_dir 中有半寫檔案，下次掃描仍能 graceful 處理
"""
from __future__ import annotations

import json
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from cypulse.cli import cli


pytestmark = pytest.mark.sit


def _mock_subprocess_run(*args, **kwargs):
    result = MagicMock()
    result.stdout = ""
    result.stderr = ""
    result.returncode = 0
    return result


def _mock_requests_get(url, *args, **kwargs):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {}
    resp.text = ""
    return resp


def _run_scan(tmpdir: str, runner: CliRunner) -> int:
    with patch("subprocess.run", side_effect=_mock_subprocess_run), \
         patch("requests.get", side_effect=_mock_requests_get), \
         patch("requests.post", side_effect=_mock_requests_get), \
         patch("cypulse.utils.subprocess.check_tool", return_value=False), \
         patch("cypulse.analysis.web_security.check_tool", return_value=False), \
         patch("cypulse.analysis.cloud_exposure.check_tool", return_value=False), \
         patch("cypulse.discovery.subfinder.check_tool", return_value=False), \
         patch("cypulse.discovery.amass.check_tool", return_value=False), \
         patch("cypulse.discovery.dnsx.check_tool", return_value=False), \
         patch("cypulse.discovery.httpx_tool.check_tool", return_value=False), \
         patch("cypulse.discovery.naabu.check_tool", return_value=False):
        result = runner.invoke(
            cli,
            ["scan", "example.com", "--output", tmpdir, "--timeout", "60"],
            catch_exceptions=False,
        )
    return result.exit_code, result.output


class TestScanDiffResilience:

    def test_two_scans_trigger_diff(self):
        """連續跑兩次 scan，第二次應產生 diff.json。"""
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            code1, _ = _run_scan(tmpdir, runner)
            assert code1 == 0
            # 等 1 秒避免兩次 scan timestamp 衝突
            import time
            time.sleep(1)
            code2, output2 = _run_scan(tmpdir, runner)
            assert code2 == 0
            # 第二次應有 Phase 5: 差異比對
            assert "差異比對" in output2 or "Phase 5" in output2

            domain_dir = os.path.join(tmpdir, "example.com")
            scans = sorted(os.listdir(domain_dir))
            assert len(scans) == 2
            second = os.path.join(domain_dir, scans[-1])
            assert os.path.isfile(os.path.join(second, "diff.json"))

    def test_atomic_write_survives_orphan_temp(self):
        """前次 scan 留下 .tmp 檔不應拖垮第二次 scan（atomic write 驗證）。"""
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            code1, _ = _run_scan(tmpdir, runner)
            assert code1 == 0

            # 模擬 scan 1 結束後留下 orphan tmp 檔
            domain_dir = os.path.join(tmpdir, "example.com")
            scans = os.listdir(domain_dir)
            scan_dir = os.path.join(domain_dir, scans[0])
            orphan = os.path.join(scan_dir, ".findings.json.orphan.tmp")
            with open(orphan, "w") as f:
                f.write("半寫")

            # 第二次 scan 不應被 orphan 拖垮
            import time
            time.sleep(1)
            code2, _ = _run_scan(tmpdir, runner)
            assert code2 == 0

            # 第二次 scan 的 findings.json 結構完整（atomic 寫入）
            scans2 = sorted(os.listdir(domain_dir))
            second = os.path.join(domain_dir, scans2[-1])
            with open(os.path.join(second, "findings.json")) as f:
                data = json.load(f)  # 不應 raise JSONDecodeError
            assert data["domain"] == "example.com"
