from click.testing import CliRunner
from cypulse.cli import cli


class TestCLI:
    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

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

    def test_schedule_no_config(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["schedule", "--targets", "/nonexistent.yaml"])
        assert result.exit_code == 0
        assert "No targets" in result.output
