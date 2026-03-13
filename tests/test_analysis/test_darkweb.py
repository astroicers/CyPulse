from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock

from cypulse.analysis.darkweb import DarkWebModule
from cypulse.models import Asset, Assets


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_assets():
    """Assets 物件，domain="example.com"，含一筆子網域記錄。"""
    return Assets(
        domain="example.com",
        timestamp="2026-03-13T000000",
        subdomains=[
            Asset(
                subdomain="www.example.com",
                ip="93.184.216.34",
                ports=[80, 443],
                http_status=200,
            )
        ],
    )


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestDarkWebModule:
    """DarkWebModule (M6) 單元測試。"""

    # ------------------------------------------------------------------
    # 1. 模組基本屬性
    # ------------------------------------------------------------------

    def test_module_info(self):
        """module_id、weight、max_score 必須符合規格。"""
        m = DarkWebModule()
        assert m.module_id() == "M6"
        assert m.weight() == 0.10
        assert m.max_score() == 10

    # ------------------------------------------------------------------
    # 2. 未設定 HIBP_API_KEY
    # ------------------------------------------------------------------

    def test_no_api_key(self, sample_assets):
        """未設定 HIBP_API_KEY 時，分數應為 0，狀態為 error，並回傳 info finding。"""
        m = DarkWebModule()

        # 確保環境中不存在 HIBP_API_KEY
        with patch.dict("os.environ", {}, clear=True):
            # 若測試環境實際上有此 key，需強制移除
            import os
            os.environ.pop("HIBP_API_KEY", None)

            result = m.run(sample_assets)

        assert result.module_id == "M6"
        assert result.score == 0
        assert result.status == "error"
        assert len(result.findings) == 1
        assert result.findings[0].severity == "info"
        assert "HIBP" in result.findings[0].title

    def test_no_api_key_via_patch_dict(self, sample_assets):
        """使用 patch.dict 確保 HIBP_API_KEY 不存在時行為一致。"""
        m = DarkWebModule()

        with patch.dict("os.environ", {}, clear=True):
            result = m.run(sample_assets)

        assert result.score == 0
        assert result.status == "error"
        # 只應有一筆 info finding，不得有其他 finding
        assert all(f.severity == "info" for f in result.findings)

    # ------------------------------------------------------------------
    # 3. 有 API key，且 HIBP 回傳多筆 breach
    # ------------------------------------------------------------------

    def test_breaches_found_single(self, sample_assets):
        """發現 1 筆 breach：severity=high，score_impact=1，score=9。"""
        m = DarkWebModule()
        fake_breaches = [{"Name": "BreachAlpha"}]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = fake_breaches

        with patch.dict("os.environ", {"HIBP_API_KEY": "fake-key"}):
            with patch("requests.get", return_value=mock_resp):
                result = m.run(sample_assets)

        assert result.status == "success"
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.severity == "high"
        assert "BreachAlpha" in finding.title
        # 1 筆 breach → impact = min(3, 1) = 1
        assert finding.score_impact == 1
        assert result.score == 9

    def test_breaches_found_multiple(self, sample_assets):
        """發現 4 筆 breach：每筆 score_impact=min(3,4)=3，score=max(0, 10-12)=0。"""
        m = DarkWebModule()
        fake_breaches = [
            {"Name": "BreachA"},
            {"Name": "BreachB"},
            {"Name": "BreachC"},
            {"Name": "BreachD"},
        ]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = fake_breaches

        with patch.dict("os.environ", {"HIBP_API_KEY": "fake-key"}):
            with patch("requests.get", return_value=mock_resp):
                result = m.run(sample_assets)

        assert result.status == "success"
        assert len(result.findings) == 4
        for finding in result.findings:
            assert finding.severity == "high"
            # 4 筆 → impact = min(3, 4) = 3
            assert finding.score_impact == 3
        # score 下限為 0
        assert result.score == 0

    def test_breaches_found_three(self, sample_assets):
        """發現剛好 3 筆 breach：score_impact=3，score=max(0, 10-9)=1。"""
        m = DarkWebModule()
        fake_breaches = [
            {"Name": "BreachX"},
            {"Name": "BreachY"},
            {"Name": "BreachZ"},
        ]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = fake_breaches

        with patch.dict("os.environ", {"HIBP_API_KEY": "fake-key"}):
            with patch("requests.get", return_value=mock_resp):
                result = m.run(sample_assets)

        assert result.status == "success"
        assert len(result.findings) == 3
        for finding in result.findings:
            assert finding.score_impact == 3
        assert result.score == 1

    def test_breaches_finding_description_contains_domain(self, sample_assets):
        """Finding description 應包含被查詢的 domain。"""
        m = DarkWebModule()
        fake_breaches = [{"Name": "SomeBreach"}]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = fake_breaches

        with patch.dict("os.environ", {"HIBP_API_KEY": "fake-key"}):
            with patch("requests.get", return_value=mock_resp):
                result = m.run(sample_assets)

        assert "example.com" in result.findings[0].description

    def test_breaches_finding_evidence_is_breach_name(self, sample_assets):
        """Finding evidence 應為 breach 的 Name 欄位值。"""
        m = DarkWebModule()
        fake_breaches = [{"Name": "EvidenceBreach"}]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = fake_breaches

        with patch.dict("os.environ", {"HIBP_API_KEY": "fake-key"}):
            with patch("requests.get", return_value=mock_resp):
                result = m.run(sample_assets)

        assert result.findings[0].evidence == "EvidenceBreach"

    # ------------------------------------------------------------------
    # 4. 有 API key，但 HIBP 回傳空清單（無 breach）
    # ------------------------------------------------------------------

    def test_no_breaches(self, sample_assets):
        """無 breach 時：score=10，status=success，findings 為空。"""
        m = DarkWebModule()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = []

        with patch.dict("os.environ", {"HIBP_API_KEY": "fake-key"}):
            with patch("requests.get", return_value=mock_resp):
                result = m.run(sample_assets)

        assert result.module_id == "M6"
        assert result.score == 10
        assert result.status == "success"
        assert result.findings == []

    # ------------------------------------------------------------------
    # 5. API 請求失敗（網路例外）
    # ------------------------------------------------------------------

    def test_api_error_network_exception(self, sample_assets):
        """requests.get 拋出例外時，應回傳空 findings，score=10，status=success。"""
        m = DarkWebModule()

        with patch.dict("os.environ", {"HIBP_API_KEY": "fake-key"}):
            with patch("requests.get", side_effect=Exception("connection timeout")):
                result = m.run(sample_assets)

        assert result.status == "success"
        assert result.score == 10
        assert result.findings == []

    def test_api_error_non_200_status(self, sample_assets):
        """HIBP 回傳非 200 狀態碼時（如 429），應視為空清單，findings 為空。"""
        m = DarkWebModule()
        mock_resp = MagicMock()
        mock_resp.status_code = 429  # Too Many Requests
        mock_resp.json.return_value = []

        with patch.dict("os.environ", {"HIBP_API_KEY": "fake-key"}):
            with patch("requests.get", return_value=mock_resp):
                result = m.run(sample_assets)

        assert result.status == "success"
        assert result.score == 10
        assert result.findings == []

    def test_api_error_connection_error(self, sample_assets):
        """requests.ConnectionError 時，_check_hibp 應回傳空清單。"""
        import requests as req_module

        m = DarkWebModule()

        with patch.dict("os.environ", {"HIBP_API_KEY": "fake-key"}):
            with patch("requests.get", side_effect=req_module.ConnectionError("unreachable")):
                result = m.run(sample_assets)

        assert result.findings == []
        assert result.score == 10

    # ------------------------------------------------------------------
    # 6. _check_hibp 內部單元測試
    # ------------------------------------------------------------------

    def test_check_hibp_passes_correct_headers_and_params(self, sample_assets):
        """_check_hibp 應帶正確的 API key header 與 domain param 呼叫 HIBP。"""
        m = DarkWebModule()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = []

        with patch("requests.get", return_value=mock_resp) as mock_get:
            m._check_hibp("example.com", "test-api-key")

        mock_get.assert_called_once()
        call_kwargs = mock_get.call_args

        # 確認 header 包含 api key
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers", {})
        assert headers.get("hibp-api-key") == "test-api-key"

        # 確認 params 包含 domain
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params", {})
        assert params.get("domain") == "example.com"

    def test_check_hibp_returns_empty_on_exception(self):
        """_check_hibp 內部例外應回傳空清單，不拋出例外。"""
        m = DarkWebModule()

        with patch("requests.get", side_effect=RuntimeError("unexpected")):
            result = m._check_hibp("example.com", "fake-key")

        assert result == []

    def test_check_hibp_returns_empty_on_non_200(self):
        """_check_hibp 收到非 200 回應時應回傳空清單。"""
        m = DarkWebModule()
        mock_resp = MagicMock()
        mock_resp.status_code = 401

        with patch("requests.get", return_value=mock_resp):
            result = m._check_hibp("example.com", "invalid-key")

        assert result == []

    # ------------------------------------------------------------------
    # 7. ModuleResult 欄位完整性
    # ------------------------------------------------------------------

    def test_result_fields_present_on_success(self, sample_assets):
        """run() 回傳的 ModuleResult 必須包含所有必要欄位。"""
        m = DarkWebModule()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = []

        with patch.dict("os.environ", {"HIBP_API_KEY": "fake-key"}):
            with patch("requests.get", return_value=mock_resp):
                result = m.run(sample_assets)

        assert result.module_id == "M6"
        assert result.module_name == "暗網憑證外洩"
        assert result.max_score == 10
        assert isinstance(result.execution_time, float)
        assert result.execution_time >= 0.0
        assert isinstance(result.raw_data, dict)

    def test_result_fields_present_on_error(self, sample_assets):
        """無 API key 情境的 ModuleResult 亦必須包含所有必要欄位。"""
        m = DarkWebModule()

        with patch.dict("os.environ", {}, clear=True):
            import os
            os.environ.pop("HIBP_API_KEY", None)
            result = m.run(sample_assets)

        assert result.module_id == "M6"
        assert result.module_name == "暗網憑證外洩"
        assert result.max_score == 10
        assert isinstance(result.execution_time, float)
