"""SIT-1: 完整 scan 流程端到端測試。

mock 所有外部 subprocess + HTTP 後執行 cypulse scan，驗證：
- exit code 0
- 寫出 assets.json / findings.json / module_M*.json / score.json / report.html / CSV
- score.json 含 confidence + source_coverage（Task H 整合）
- HTML 含「信心」徽章（Task N 整合）

**SIT 標記**：`pytest -m sit` 才會跑；預設 `make test` 不跑。
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
    """所有 subprocess.run 都回傳空輸出（工具未安裝/未發現問題）。"""
    result = MagicMock()
    result.stdout = ""
    result.stderr = ""
    result.returncode = 0
    return result


def _mock_requests_get(url, *args, **kwargs):
    """所有 HTTP GET 都回傳 200 + 空 JSON（API 沒命中）。"""
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {}
    resp.text = ""
    return resp


def _mock_check_tool(name):
    """所有外部工具視為「未安裝」，模組會走 graceful skip 路徑。"""
    return False


class TestFullScanFlow:
    """端到端：scan example.com（無外部依賴），驗證所有檔案產出與 schema。"""

    def test_full_scan_produces_all_outputs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
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

                runner = CliRunner()
                result = runner.invoke(
                    cli,
                    ["scan", "example.com", "--output", tmpdir, "--timeout", "60"],
                    catch_exceptions=False,
                )

            # 1. CLI 成功結束
            assert result.exit_code == 0, f"scan failed: {result.output}"

            # 2. 找到 scan_dir
            domain_dir = os.path.join(tmpdir, "example.com")
            assert os.path.isdir(domain_dir)
            scans = os.listdir(domain_dir)
            assert len(scans) == 1
            scan_dir = os.path.join(domain_dir, scans[0])

            # 3. 預期所有輸出檔存在
            expected_files = [
                "assets.json", "findings.json", "score.json",
                "report.html", "assets.csv", "findings.csv",
            ]
            for fname in expected_files:
                fpath = os.path.join(scan_dir, fname)
                assert os.path.isfile(fpath), f"缺少 {fname}"

            # 4. 每個模組各一份 module_Mn.json
            from cypulse.scoring.weights import WEIGHTS
            for mid in WEIGHTS:
                fpath = os.path.join(scan_dir, f"module_{mid}.json")
                assert os.path.isfile(fpath), f"缺少 {fpath}"

            # 5. score.json schema 含 Task H 新欄位
            with open(os.path.join(scan_dir, "score.json")) as f:
                score_data = json.load(f)
            assert "confidence" in score_data
            assert "source_coverage" in score_data
            assert isinstance(score_data["confidence"], (int, float))
            assert isinstance(score_data["source_coverage"], dict)

            # 6. HTML 含 Task N 視覺元素
            with open(os.path.join(scan_dir, "report.html"), encoding="utf-8") as f:
                html = f.read()
            assert "信心" in html
            assert "CyPulse" in html

            # 7. CLI 輸出含 SCAN COMPLETE 摘要
            assert "SCAN COMPLETE" in result.output

    def test_scan_with_invalid_module_aborts_early(self):
        """sanity：無效 module 不會跑到 Phase 1。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = CliRunner()
            result = runner.invoke(
                cli,
                ["scan", "example.com", "--modules", "M99", "--output", tmpdir],
            )
            assert result.exit_code != 0
            assert "M99" in result.output
            # 不應建立 scan_dir
            assert not os.path.isdir(os.path.join(tmpdir, "example.com"))
