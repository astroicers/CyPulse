from click.testing import CliRunner
from cypulse.cli import cli


class TestCLI:
    def test_version(self):
        """CLI 版本應從 pyproject 動態讀取（或同步顯示當前版本）。"""
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        # 不硬寫版本號；只驗證為 semver 格式
        import re
        assert re.search(r"\d+\.\d+\.\d+", result.output), (
            f"--version 輸出無 semver 格式：{result.output!r}"
        )

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "CyPulse" in result.output
        assert "scan" in result.output
        assert "report" in result.output
        assert "diff" in result.output

    def test_scan_invalid_domain(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "not a domain!!!"])
        assert result.exit_code != 0

    def test_scan_invalid_module_id_rejected(self):
        """scan --modules M9 應拒絕並提示有效模組清單。"""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "example.com", "--modules", "M9"])
        assert result.exit_code != 0
        assert "Unknown modules" in result.output
        assert "M9" in result.output

    def test_scan_mixed_valid_invalid_modules(self):
        """混合 M1（有效）+ M99（無效），應因 M99 而中止，不能部分執行。"""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "example.com", "--modules", "M1,M99"])
        assert result.exit_code != 0
        assert "M99" in result.output

    def test_scan_export_logs_writes_jsonl(self, tmp_path):
        """--export-logs PATH 應在 scan 結束時寫出 jsonl 檔，含 scan_id。"""
        from unittest.mock import patch
        runner = CliRunner()
        log_path = tmp_path / "scan.jsonl"
        out_dir = tmp_path / "data"
        with patch("subprocess.run") as mock_run, \
             patch("requests.get") as mock_get, \
             patch("requests.post") as mock_post, \
             patch("cypulse.utils.subprocess.check_tool", return_value=False), \
             patch("cypulse.analysis.web_security.check_tool", return_value=False), \
             patch("cypulse.analysis.cloud_exposure.check_tool", return_value=False), \
             patch("cypulse.discovery.subfinder.check_tool", return_value=False), \
             patch("cypulse.discovery.amass.check_tool", return_value=False), \
             patch("cypulse.discovery.dnsx.check_tool", return_value=False), \
             patch("cypulse.discovery.httpx_tool.check_tool", return_value=False), \
             patch("cypulse.discovery.naabu.check_tool", return_value=False):
            mock_run.return_value.stdout = ""
            mock_run.return_value.returncode = 0
            mock_get.return_value.status_code = 200
            mock_get.return_value.json.return_value = {}
            mock_get.return_value.text = ""
            mock_post.return_value = mock_get.return_value

            result = runner.invoke(
                cli,
                ["scan", "example.com",
                 "--output", str(out_dir),
                 "--export-logs", str(log_path),
                 "--timeout", "60"],
            )
        assert result.exit_code == 0, f"scan failed: {result.output}"
        assert log_path.exists(), "--export-logs 檔案未產生"
        # 驗證為 valid jsonl（每行 valid JSON）+ 含 scan_id
        import json as _json
        lines = log_path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) > 0
        for line in lines:
            data = _json.loads(line)  # 每行是 valid JSON
            assert "scan_id" in data, f"event 缺 scan_id: {data}"

    def test_list_modules_outputs_all(self):
        """`cypulse list-modules` 應印出所有 M1-M8 + 名稱 + 權重 + 滿分。"""
        runner = CliRunner()
        result = runner.invoke(cli, ["list-modules"])
        assert result.exit_code == 0
        for mid in ["M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8"]:
            assert mid in result.output, f"{mid} not in output"
        # 至少出現權重格式（百分比或小數）
        assert "%" in result.output or "weight" in result.output.lower() or "權重" in result.output

    def test_scan_dry_run_does_not_execute_phases(self):
        """--dry-run 應顯示要做什麼但不真的呼叫 run_discovery。"""
        from unittest.mock import patch
        runner = CliRunner()
        with patch("cypulse.discovery.pipeline.run_discovery") as mock_run, \
             patch("cypulse.utils.subprocess.check_tool", return_value=True):
            result = runner.invoke(cli, ["scan", "example.com", "--dry-run"])
        assert result.exit_code == 0
        mock_run.assert_not_called()
        # 輸出應提示「dry-run」與會執行的模組
        assert "dry" in result.output.lower() or "預檢" in result.output
        assert "M1" in result.output or "module" in result.output.lower()

    def test_scan_dry_run_reports_missing_tools(self):
        """--dry-run 應檢查工具是否安裝，缺少時顯示 missing 清單。"""
        from unittest.mock import patch
        runner = CliRunner()
        with patch("cypulse.utils.subprocess.check_tool", return_value=False):
            result = runner.invoke(cli, ["scan", "example.com", "--dry-run"])
        # exit code 0 或 1 都接受（缺工具是 warning 不一定失敗）
        # 但輸出必須提到「未安裝」「missing」「not installed」之一
        assert any(
            kw in result.output.lower() or kw in result.output
            for kw in ["未安裝", "missing", "not installed"]
        ), f"dry-run 應警示缺工具: {result.output!r}"

    def test_scan_dry_run_with_invalid_module_still_rejects(self):
        """--dry-run 也應拒絕無效 module ID。"""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "example.com", "--modules", "M99", "--dry-run"])
        assert result.exit_code != 0
        assert "M99" in result.output

    def test_scan_score_json_includes_scan_id(self, tmp_path):
        """scan 完成後 score.json 應含 scan_id 欄位。"""
        from unittest.mock import patch
        import json as _json
        runner = CliRunner()
        out_dir = tmp_path / "data"
        with patch("subprocess.run") as mock_run, \
             patch("requests.get") as mock_get, \
             patch("requests.post") as mock_post, \
             patch("cypulse.utils.subprocess.check_tool", return_value=False), \
             patch("cypulse.analysis.web_security.check_tool", return_value=False), \
             patch("cypulse.analysis.cloud_exposure.check_tool", return_value=False), \
             patch("cypulse.discovery.subfinder.check_tool", return_value=False), \
             patch("cypulse.discovery.amass.check_tool", return_value=False), \
             patch("cypulse.discovery.dnsx.check_tool", return_value=False), \
             patch("cypulse.discovery.httpx_tool.check_tool", return_value=False), \
             patch("cypulse.discovery.naabu.check_tool", return_value=False):
            mock_run.return_value.stdout = ""
            mock_run.return_value.returncode = 0
            mock_get.return_value.status_code = 200
            mock_get.return_value.json.return_value = {}
            mock_get.return_value.text = ""
            mock_post.return_value = mock_get.return_value

            result = runner.invoke(
                cli,
                ["scan", "example.com", "--output", str(out_dir), "--timeout", "60"],
            )
        assert result.exit_code == 0
        # 找 score.json
        domain_dir = out_dir / "example.com"
        scans = list(domain_dir.iterdir())
        score_data = _json.loads((scans[0] / "score.json").read_text())
        assert score_data.get("scan_id"), f"score.json 缺 scan_id: {score_data}"
        assert len(score_data["scan_id"]) == 12, "scan_id 應為 uuid hex 前 12 字"
