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
