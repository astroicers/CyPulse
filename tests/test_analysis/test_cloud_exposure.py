from unittest.mock import patch, MagicMock
import pytest
from cypulse.analysis.cloud_exposure import CloudExposureModule
from cypulse.models import Asset, Assets


@pytest.fixture
def sample_assets():
    return Assets(
        domain="example.com",
        timestamp="2026-03-16T000000",
        subdomains=[Asset(subdomain="www.example.com", ip="1.2.3.4", ports=[443])],
    )


class TestCloudExposureModule:
    def test_module_info(self):
        m = CloudExposureModule()
        assert m.module_id() == "M8"
        assert m.weight() == 0.04
        assert m.max_score() == 4

    def test_s3scanner_not_installed(self, sample_assets):
        """s3scanner 未安裝 → source=skipped，按規則 skipped 不計入失敗 → status=success。"""
        m = CloudExposureModule()
        with patch("cypulse.analysis.cloud_exposure.check_tool", return_value=False):
            result = m.run(sample_assets)
        assert result.module_id == "M8"
        info_findings = [f for f in result.findings if f.severity == "info"]
        assert len(info_findings) >= 1
        assert len(result.sources) == 1
        assert result.sources[0].source_id == "s3scanner"
        assert result.sources[0].status == "skipped"
        # skipped 不算失敗，但信心分數（Task H）會反映未覆蓋
        assert result.status == "success"

    def test_s3scanner_runtime_error(self, sample_assets):
        """s3scanner 執行時拋 TimeoutExpired → status=error（唯一 core 失敗）。"""
        import subprocess
        m = CloudExposureModule()
        with patch("cypulse.analysis.cloud_exposure.check_tool", return_value=True), \
             patch(
                 "cypulse.analysis.cloud_exposure.run_cmd",
                 side_effect=subprocess.TimeoutExpired(cmd="s3scanner", timeout=60),
             ):
            result = m.run(sample_assets)
        assert result.status == "error"
        assert len(result.sources) == 1
        assert result.sources[0].status == "failed"
        assert "runtime_error" in (result.sources[0].error or "")

    def test_no_public_buckets(self, sample_assets):
        """無公開 bucket 時，應滿分，無 non-info findings。"""
        mock_result = MagicMock()
        mock_result.stdout = '{"bucket": "example-com", "exists": false}\n'
        mock_result.returncode = 0
        m = CloudExposureModule()
        with patch("cypulse.analysis.cloud_exposure.check_tool", return_value=True), \
             patch("cypulse.analysis.cloud_exposure.run_cmd", return_value=mock_result):
            result = m.run(sample_assets)
        bucket_findings = [f for f in result.findings if f.severity != "info"]
        assert len(bucket_findings) == 0
        assert result.score == m.max_score()

    def test_public_read_bucket_found(self, sample_assets):
        """S3Scanner 偵測到公開可讀 bucket 時應產生 high finding。"""
        mock_result = MagicMock()
        mock_result.stdout = (
            '{"bucket": "example-com", "exists": true, '
            '"public_read": true, "region": "us-east-1"}\n'
        )
        mock_result.returncode = 0
        m = CloudExposureModule()
        with patch("cypulse.analysis.cloud_exposure.check_tool", return_value=True), \
             patch("cypulse.analysis.cloud_exposure.run_cmd", return_value=mock_result):
            result = m.run(sample_assets)
        bucket_findings = [f for f in result.findings if f.severity in ("high", "critical")]
        assert len(bucket_findings) >= 1
        assert any("example-com" in f.title for f in bucket_findings)

    def test_public_write_bucket_critical(self, sample_assets):
        """公開可寫 bucket 應產生 critical finding。"""
        mock_result = MagicMock()
        mock_result.stdout = (
            '{"bucket": "backup-example-com", "exists": true, '
            '"public_write": true, "region": "eu-west-1"}\n'
        )
        mock_result.returncode = 0
        m = CloudExposureModule()
        with patch("cypulse.analysis.cloud_exposure.check_tool", return_value=True), \
             patch("cypulse.analysis.cloud_exposure.run_cmd", return_value=mock_result):
            result = m.run(sample_assets)
        critical = [f for f in result.findings if f.severity == "critical"]
        assert len(critical) >= 1

    def test_score_deducted_for_public_bucket(self, sample_assets):
        """發現公開可讀 bucket 應扣分。"""
        mock_result = MagicMock()
        mock_result.stdout = '{"bucket": "example-com", "exists": true, "public_read": true}\n'
        mock_result.returncode = 0
        m = CloudExposureModule()
        with patch("cypulse.analysis.cloud_exposure.check_tool", return_value=True), \
             patch("cypulse.analysis.cloud_exposure.run_cmd", return_value=mock_result):
            result = m.run(sample_assets)
        assert result.score < m.max_score()
        assert result.score >= 0
