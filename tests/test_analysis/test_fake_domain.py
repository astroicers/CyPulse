from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock

from cypulse.analysis.fake_domain import FakeDomainModule
from cypulse.models import Asset, Assets


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_assets():
    return Assets(
        domain="example.com",
        timestamp="2026-03-13T000000",
        subdomains=[
            Asset(subdomain="www.example.com", ip="93.184.216.34", ports=[80, 443]),
        ],
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestFakeDomainModule:
    """M7 FakeDomainModule 單元測試"""

    # ------------------------------------------------------------------
    # 模組基本資訊
    # ------------------------------------------------------------------

    def test_module_info(self):
        """module_id、weight、max_score 應符合規格"""
        m = FakeDomainModule()
        assert m.module_id() == "M7"
        assert m.module_name() == "偽冒域名偵測"
        assert m.weight() == pytest.approx(0.05)
        assert m.max_score() == 5

    # ------------------------------------------------------------------
    # dnstwist 無法使用（ImportError）→ score=0, status="error"
    # ------------------------------------------------------------------

    def test_dnstwist_unavailable(self, sample_assets):
        """_run_dnstwist 回傳 None（dnstwist 未安裝）時，score 應為 0，status 為 error"""
        m = FakeDomainModule()
        with patch.object(FakeDomainModule, "_run_dnstwist", return_value=None):
            result = m.run(sample_assets)

        assert result.module_id == "M7"
        assert result.score == 0
        assert result.max_score == 5
        assert result.status == "error"
        # 應包含一筆 info finding 說明原因
        assert len(result.findings) == 1
        assert result.findings[0].severity == "info"
        assert "dnstwist" in result.findings[0].title.lower()

    # ------------------------------------------------------------------
    # dnstwist 回傳已解析的偽冒域名（有 dns_a）→ severity=medium, score_impact=1 each
    # ------------------------------------------------------------------

    def test_resolved_fake_domains_reduces_score(self, sample_assets):
        """每個已解析的偽冒域名扣 1 分（最多 5 個），severity 必須為 medium"""
        fake_data = [
            {"domain": "examp1e.com", "fuzzer": "replacement", "dns_a": ["1.2.3.4"]},
            {"domain": "exarnple.com", "fuzzer": "replacement", "dns_a": ["5.6.7.8"]},
            {"domain": "exampIe.com", "fuzzer": "homoglyph",   "dns_a": ["9.10.11.12"]},
        ]
        m = FakeDomainModule()
        with patch.object(FakeDomainModule, "_run_dnstwist", return_value=fake_data):
            result = m.run(sample_assets)

        assert result.status == "success"
        assert result.score == 2          # 5 - 3 = 2
        assert result.max_score == 5
        assert len(result.findings) == 3
        for finding in result.findings:
            assert finding.severity == "medium"
            assert finding.score_impact == 1

    def test_resolved_fake_domains_capped_at_five(self, sample_assets):
        """超過 5 個已解析的偽冒域名，分數最低扣到 0，findings 也只取前 5 筆"""
        fake_data = [
            {"domain": f"exa{i}mple.com", "fuzzer": "replacement", "dns_a": [f"1.2.3.{i}"]}
            for i in range(8)
        ]
        m = FakeDomainModule()
        with patch.object(FakeDomainModule, "_run_dnstwist", return_value=fake_data):
            result = m.run(sample_assets)

        assert result.status == "success"
        assert result.score == 0          # 5 - 5 = 0（上限）
        assert len(result.findings) == 5  # 只處理前 5 筆

    def test_resolved_via_dns_aaaa(self, sample_assets):
        """dns_aaaa 欄位也應視為已解析，納入偵測"""
        fake_data = [
            {"domain": "exampIe.com", "fuzzer": "homoglyph", "dns_aaaa": ["::1"]},
        ]
        m = FakeDomainModule()
        with patch.object(FakeDomainModule, "_run_dnstwist", return_value=fake_data):
            result = m.run(sample_assets)

        assert result.score == 4          # 5 - 1 = 4
        assert len(result.findings) == 1
        assert result.findings[0].severity == "medium"

    # ------------------------------------------------------------------
    # dnstwist 回傳但沒有任何已解析域名 → score=5
    # ------------------------------------------------------------------

    def test_no_resolved_domains(self, sample_assets):
        """dnstwist 回傳結果但全部未解析時，score 應為滿分 5，無 findings"""
        fake_data = [
            {"domain": "examp1e.com", "fuzzer": "replacement"},           # 無 dns_a / dns_aaaa
            {"domain": "exarnple.com", "fuzzer": "replacement", "dns_a": []},  # 空串列
        ]
        m = FakeDomainModule()
        with patch.object(FakeDomainModule, "_run_dnstwist", return_value=fake_data):
            result = m.run(sample_assets)

        assert result.status == "success"
        assert result.score == 5
        assert result.findings == []

    def test_empty_dnstwist_result(self, sample_assets):
        """dnstwist 回傳空清單時，score 應為滿分 5"""
        m = FakeDomainModule()
        with patch.object(FakeDomainModule, "_run_dnstwist", return_value=[]):
            result = m.run(sample_assets)

        assert result.status == "success"
        assert result.score == 5
        assert result.findings == []

    # ------------------------------------------------------------------
    # dnstwist 拋出例外 → _run_dnstwist 回傳 None → score=0, status="error"
    # ------------------------------------------------------------------

    def test_dnstwist_exception(self, sample_assets):
        """_run_dnstwist 遭遇例外回傳 None 時，行為應與 ImportError 相同"""
        m = FakeDomainModule()
        with patch.object(FakeDomainModule, "_run_dnstwist", return_value=None):
            result = m.run(sample_assets)

        assert result.score == 0
        assert result.status == "error"

    # ------------------------------------------------------------------
    # _run_dnstwist 內部行為：ImportError 路徑
    # ------------------------------------------------------------------

    def test_run_dnstwist_returns_none_on_import_error(self, sample_assets):
        """當 dnstwist 模組不存在時，_run_dnstwist 應直接回傳 None"""
        import sys
        m = FakeDomainModule()
        # 以 sys.modules 注入 None 模擬 dnstwist 未安裝
        with patch.dict(sys.modules, {"dnstwist": None}):
            result = m._run_dnstwist("example.com")
        assert result is None

    # ------------------------------------------------------------------
    # _run_dnstwist 內部行為：正常路徑（Fuzzer mock）
    # ------------------------------------------------------------------

    def test_run_dnstwist_normal_path(self):
        """_run_dnstwist 正常執行時，應回傳 Fuzzer.domains 轉換後的 list[dict]"""
        mock_domain_a = {"domain": "examp1e.com", "fuzzer": "replacement", "dns_a": ["1.2.3.4"]}
        mock_domain_b = {"domain": "exarnple.com", "fuzzer": "replacement"}

        mock_fuzzer_instance = MagicMock()
        mock_fuzzer_instance.domains = [mock_domain_a, mock_domain_b]

        mock_dnstwist = MagicMock()
        mock_dnstwist.Fuzzer.return_value = mock_fuzzer_instance

        import sys
        m = FakeDomainModule()
        with patch.dict(sys.modules, {"dnstwist": mock_dnstwist}):
            result = m._run_dnstwist("example.com")

        mock_dnstwist.Fuzzer.assert_called_once_with("example.com")
        mock_fuzzer_instance.generate.assert_called_once()
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0] == dict(mock_domain_a)

    def test_run_dnstwist_returns_none_on_fuzzer_exception(self):
        """Fuzzer 拋出例外時，_run_dnstwist 應捕捉後回傳 None"""
        mock_fuzzer_instance = MagicMock()
        mock_fuzzer_instance.generate.side_effect = RuntimeError("network error")

        mock_dnstwist = MagicMock()
        mock_dnstwist.Fuzzer.return_value = mock_fuzzer_instance

        import sys
        m = FakeDomainModule()
        with patch.dict(sys.modules, {"dnstwist": mock_dnstwist}):
            result = m._run_dnstwist("example.com")

        assert result is None

    # ------------------------------------------------------------------
    # 結果欄位完整性
    # ------------------------------------------------------------------

    def test_result_fields_complete(self, sample_assets):
        """ModuleResult 所有必填欄位都應正確填充"""
        m = FakeDomainModule()
        with patch.object(FakeDomainModule, "_run_dnstwist", return_value=[]):
            result = m.run(sample_assets)

        assert result.module_id == "M7"
        assert result.module_name == "偽冒域名偵測"
        assert result.max_score == 5
        assert isinstance(result.execution_time, float)
        assert result.execution_time >= 0
        assert result.raw_data == {}
