from __future__ import annotations
import os
from unittest.mock import MagicMock, patch

import pytest

from cypulse.analysis.ip_reputation import IPReputationModule
from cypulse.models import Asset, Assets


class TestIPReputationModule:
    # ------------------------------------------------------------------
    # 模組基本資訊
    # ------------------------------------------------------------------

    def test_module_info(self):
        m = IPReputationModule()
        assert m.module_id() == "M2"
        assert m.module_name() == "IP 信譽"
        assert m.weight() == 0.15
        assert m.max_score() == 15

    # ------------------------------------------------------------------
    # 無 API Key 情境
    # ------------------------------------------------------------------

    def test_no_api_key(self, sample_assets):
        """未設定 ABUSEIPDB_API_KEY 時，score=0、status=error，並回傳 info finding。"""
        m = IPReputationModule()
        with patch.dict(os.environ, {}, clear=True):
            # 確保 key 不存在
            os.environ.pop("ABUSEIPDB_API_KEY", None)
            result = m.run(sample_assets)

        assert result.module_id == "M2"
        assert result.score == 0
        assert result.status == "error"
        assert len(result.findings) == 1
        assert result.findings[0].severity == "info"
        # title 包含 "AbuseIPDB API key"，description 包含環境變數名稱
        assert "AbuseIPDB" in result.findings[0].title
        assert "ABUSEIPDB_API_KEY" in result.findings[0].description

    # ------------------------------------------------------------------
    # 高風險 IP（abuse score > 50）
    # ------------------------------------------------------------------

    def test_high_abuse_score(self, sample_assets):
        """API 回傳 abuseConfidenceScore > 50 時，產生 high severity finding，score_impact=10。"""
        m = IPReputationModule()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "abuseConfidenceScore": 85,
                "totalReports": 42,
            }
        }

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch("requests.get", return_value=mock_resp):
                result = m.run(sample_assets)

        assert result.status == "success"
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.severity == "high"
        assert finding.score_impact == 10
        # score 應從 max_score 扣除 score_impact
        assert result.score == m.max_score() - 10

    # ------------------------------------------------------------------
    # 中風險 IP（20 < abuse score <= 50）
    # ------------------------------------------------------------------

    def test_medium_abuse_score(self, sample_assets):
        """API 回傳 20 < abuseConfidenceScore <= 50 時，產生 medium severity finding，score_impact=5。"""
        m = IPReputationModule()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "abuseConfidenceScore": 35,
                "totalReports": 5,
            }
        }

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch("requests.get", return_value=mock_resp):
                result = m.run(sample_assets)

        assert result.status == "success"
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.severity == "medium"
        assert finding.score_impact == 5
        assert result.score == m.max_score() - 5

    # ------------------------------------------------------------------
    # 乾淨 IP（abuse score <= 20）
    # ------------------------------------------------------------------

    def test_clean_ip(self, sample_assets):
        """API 回傳 abuseConfidenceScore <= 20 時，不產生 finding，score 維持滿分。"""
        m = IPReputationModule()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "abuseConfidenceScore": 0,
                "totalReports": 0,
            }
        }

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch("requests.get", return_value=mock_resp):
                result = m.run(sample_assets)

        assert result.status == "success"
        assert result.score == m.max_score()
        assert len(result.findings) == 0

    # ------------------------------------------------------------------
    # 無 IP 資產（空 subdomains）
    # ------------------------------------------------------------------

    def test_no_ips(self):
        """subdomains 中無任何 IP 時，score=max_score，不產生 finding。"""
        assets = Assets(
            domain="example.com",
            timestamp="test",
            subdomains=[
                Asset(subdomain="www.example.com"),  # ip 預設為 None
            ],
        )
        m = IPReputationModule()

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            # requests.get 不應被呼叫
            with patch("requests.get") as mock_get:
                result = m.run(assets)
                mock_get.assert_not_called()

        assert result.status == "success"
        assert result.score == m.max_score()
        assert len(result.findings) == 0

    def test_empty_subdomains(self):
        """subdomains 完全為空時，score=max_score，不產生 finding。"""
        assets = Assets(domain="example.com", timestamp="test", subdomains=[])
        m = IPReputationModule()

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch("requests.get") as mock_get:
                result = m.run(assets)
                mock_get.assert_not_called()

        assert result.status == "success"
        assert result.score == m.max_score()
        assert len(result.findings) == 0

    # ------------------------------------------------------------------
    # API 請求失敗
    # ------------------------------------------------------------------

    def test_api_error_non_200_status(self, sample_assets):
        """API 回傳非 200 狀態碼時，_check_abuseipdb 回傳 None，不產生 finding。"""
        m = IPReputationModule()
        mock_resp = MagicMock()
        mock_resp.status_code = 429  # Too Many Requests

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch("requests.get", return_value=mock_resp):
                result = m.run(sample_assets)

        assert result.status == "success"
        assert result.score == m.max_score()
        assert len(result.findings) == 0

    def test_api_error_request_exception(self, sample_assets):
        """requests.get 拋出例外時，_check_abuseipdb 回傳 None，不產生 finding，不崩潰。"""
        m = IPReputationModule()

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch("requests.get", side_effect=Exception("連線逾時")):
                result = m.run(sample_assets)

        assert result.status == "success"
        assert result.score == m.max_score()
        assert len(result.findings) == 0

    # ------------------------------------------------------------------
    # score 不得低於 0（防止負分）
    # ------------------------------------------------------------------

    def test_score_floor_at_zero(self):
        """多個高風險 IP 累積扣分時，score 不應低於 0。"""
        assets = Assets(
            domain="example.com",
            timestamp="test",
            subdomains=[
                Asset(subdomain="a.example.com", ip="1.1.1.1"),
                Asset(subdomain="b.example.com", ip="2.2.2.2"),
            ],
        )
        m = IPReputationModule()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {"abuseConfidenceScore": 99, "totalReports": 100}
        }

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch("requests.get", return_value=mock_resp):
                result = m.run(assets)

        assert result.score >= 0
