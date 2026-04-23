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


def _mock_hibp_response(breaches: list[dict]) -> MagicMock:
    """建立 HIBP 公開端點的 mock response。"""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = breaches
    return mock_resp


def _mock_comb_response(count: int, domain: str = "example.com") -> MagicMock:
    """建立 ProxyNova COMB 的 mock response。

    `count` 為期望模組實際計入的筆數（已過濾 email @domain suffix 後）。
    lines 會同步生成 count 筆符合 suffix 的資料，以便模組過濾邏輯能命中。
    """
    lines = [f"user{i}@{domain}:pw{i}" for i in range(count)]
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"count": count, "lines": lines}
    return mock_resp


def _mock_leakcheck_response(found: int = 0, sources: list | None = None) -> MagicMock:
    """建立 LeakCheck Public API 的 mock response。"""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "success": True,
        "found": found,
        "fields": ["password", "username"],
        "sources": sources or [],
    }
    return mock_resp


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
    # 2. HIBP 公開端點 — 外洩事件比對
    # ------------------------------------------------------------------

    def test_hibp_breach_found_single(self, sample_assets):
        """HIBP 清單中有 1 筆匹配域名的外洩事件。"""
        m = DarkWebModule()
        all_breaches = [
            {"Name": "ExampleBreach", "Domain": "example.com", "PwnCount": 1000},
            {"Name": "OtherBreach", "Domain": "other.com", "PwnCount": 5000},
        ]
        hibp_resp = _mock_hibp_response(all_breaches)
        comb_resp = _mock_comb_response(0)
        lc_resp = _mock_leakcheck_response(0)

        with patch("requests.get", side_effect=[hibp_resp, comb_resp, lc_resp]):
            result = m.run(sample_assets)

        assert result.status == "success"
        hibp_findings = [f for f in result.findings if "Breach:" in f.title]
        assert len(hibp_findings) == 1
        assert "ExampleBreach" in hibp_findings[0].title
        assert hibp_findings[0].severity == "high"
        assert hibp_findings[0].score_impact == 1  # min(3, 1)

    def test_hibp_breach_found_multiple(self, sample_assets):
        """HIBP 清單中有多筆匹配域名的外洩事件。"""
        m = DarkWebModule()
        all_breaches = [
            {"Name": "BreachA", "Domain": "example.com", "PwnCount": 100},
            {"Name": "BreachB", "Domain": "example.com", "PwnCount": 200},
            {"Name": "BreachC", "Domain": "example.com", "PwnCount": 300},
            {"Name": "BreachD", "Domain": "example.com", "PwnCount": 400},
            {"Name": "Unrelated", "Domain": "other.com", "PwnCount": 999},
        ]
        hibp_resp = _mock_hibp_response(all_breaches)
        comb_resp = _mock_comb_response(0)
        lc_resp = _mock_leakcheck_response(0)

        with patch("requests.get", side_effect=[hibp_resp, comb_resp, lc_resp]):
            result = m.run(sample_assets)

        hibp_findings = [f for f in result.findings if "Breach:" in f.title]
        assert len(hibp_findings) == 4
        for f in hibp_findings:
            assert f.score_impact == 3  # min(3, 4)

    def test_hibp_no_breach(self, sample_assets):
        """HIBP 清單中無匹配域名的外洩事件。"""
        m = DarkWebModule()
        all_breaches = [
            {"Name": "Other", "Domain": "other.com", "PwnCount": 1000},
        ]
        hibp_resp = _mock_hibp_response(all_breaches)
        comb_resp = _mock_comb_response(0)
        lc_resp = _mock_leakcheck_response(0)

        with patch("requests.get", side_effect=[hibp_resp, comb_resp, lc_resp]):
            result = m.run(sample_assets)

        assert result.score == 10
        assert result.findings == []

    def test_hibp_domain_case_insensitive(self, sample_assets):
        """HIBP 域名比對應不區分大小寫。"""
        m = DarkWebModule()
        all_breaches = [
            {"Name": "CaseBreach", "Domain": "Example.COM", "PwnCount": 50},
        ]
        hibp_resp = _mock_hibp_response(all_breaches)
        comb_resp = _mock_comb_response(0)
        lc_resp = _mock_leakcheck_response(0)

        with patch("requests.get", side_effect=[hibp_resp, comb_resp, lc_resp]):
            result = m.run(sample_assets)

        hibp_findings = [f for f in result.findings if "Breach:" in f.title]
        assert len(hibp_findings) == 1

    def test_hibp_breach_description_contains_domain(self, sample_assets):
        """Finding description 應包含被查詢的 domain。"""
        m = DarkWebModule()
        all_breaches = [
            {"Name": "SomeBreach", "Domain": "example.com", "PwnCount": 42},
        ]
        hibp_resp = _mock_hibp_response(all_breaches)
        comb_resp = _mock_comb_response(0)
        lc_resp = _mock_leakcheck_response(0)

        with patch("requests.get", side_effect=[hibp_resp, comb_resp, lc_resp]):
            result = m.run(sample_assets)

        assert "example.com" in result.findings[0].description

    def test_hibp_breach_evidence_is_breach_name(self, sample_assets):
        """Finding evidence 應為 breach 的 Name 欄位值。"""
        m = DarkWebModule()
        all_breaches = [
            {"Name": "EvidenceBreach", "Domain": "example.com", "PwnCount": 1},
        ]
        hibp_resp = _mock_hibp_response(all_breaches)
        comb_resp = _mock_comb_response(0)
        lc_resp = _mock_leakcheck_response(0)

        with patch("requests.get", side_effect=[hibp_resp, comb_resp, lc_resp]):
            result = m.run(sample_assets)

        assert result.findings[0].evidence == "EvidenceBreach"

    # ------------------------------------------------------------------
    # 3. ProxyNova COMB — 外洩帳號密碼數量
    # ------------------------------------------------------------------

    def test_comb_high_count(self, sample_assets):
        """COMB 回傳 >100 筆時，severity=high，score_impact=3。"""
        m = DarkWebModule()
        hibp_resp = _mock_hibp_response([])
        comb_resp = _mock_comb_response(500)

        lc_resp = _mock_leakcheck_response(0)
        with patch("requests.get", side_effect=[hibp_resp, comb_resp, lc_resp]):
            result = m.run(sample_assets)

        comb_findings = [f for f in result.findings if "外洩帳號密碼" in f.title]
        assert len(comb_findings) == 1
        assert comb_findings[0].severity == "high"
        assert comb_findings[0].score_impact == 3
        assert result.score == 7

    def test_comb_medium_count(self, sample_assets):
        """COMB 回傳 11-100 筆時，severity=medium，score_impact=2。"""
        m = DarkWebModule()
        hibp_resp = _mock_hibp_response([])
        comb_resp = _mock_comb_response(50)

        lc_resp = _mock_leakcheck_response(0)
        with patch("requests.get", side_effect=[hibp_resp, comb_resp, lc_resp]):
            result = m.run(sample_assets)

        comb_findings = [f for f in result.findings if "外洩帳號密碼" in f.title]
        assert len(comb_findings) == 1
        assert comb_findings[0].severity == "medium"
        assert comb_findings[0].score_impact == 2
        assert result.score == 8

    def test_comb_low_count(self, sample_assets):
        """COMB 回傳 1-10 筆時，severity=low，score_impact=1。"""
        m = DarkWebModule()
        hibp_resp = _mock_hibp_response([])
        comb_resp = _mock_comb_response(5)

        lc_resp = _mock_leakcheck_response(0)
        with patch("requests.get", side_effect=[hibp_resp, comb_resp, lc_resp]):
            result = m.run(sample_assets)

        comb_findings = [f for f in result.findings if "外洩帳號密碼" in f.title]
        assert len(comb_findings) == 1
        assert comb_findings[0].severity == "low"
        assert comb_findings[0].score_impact == 1
        assert result.score == 9

    def test_comb_zero_count(self, sample_assets):
        """COMB 回傳 0 筆時，不應產生 finding。"""
        m = DarkWebModule()
        hibp_resp = _mock_hibp_response([])
        comb_resp = _mock_comb_response(0)
        lc_resp = _mock_leakcheck_response(0)

        with patch("requests.get", side_effect=[hibp_resp, comb_resp, lc_resp]):
            result = m.run(sample_assets)

        assert result.findings == []
        assert result.score == 10

    def test_comb_finding_description_contains_domain(self, sample_assets):
        """COMB finding description 應包含域名。"""
        m = DarkWebModule()
        hibp_resp = _mock_hibp_response([])
        comb_resp = _mock_comb_response(25)

        lc_resp = _mock_leakcheck_response(0)
        with patch("requests.get", side_effect=[hibp_resp, comb_resp, lc_resp]):
            result = m.run(sample_assets)

        comb_findings = [f for f in result.findings if "外洩帳號密碼" in f.title]
        assert "example.com" in comb_findings[0].description

    # ------------------------------------------------------------------
    # 4. 雙來源組合
    # ------------------------------------------------------------------

    def test_both_sources_have_findings(self, sample_assets):
        """HIBP + COMB 同時有結果時，findings 應合併，分數正確扣減。"""
        m = DarkWebModule()
        all_breaches = [
            {"Name": "BreachX", "Domain": "example.com", "PwnCount": 100},
        ]
        hibp_resp = _mock_hibp_response(all_breaches)
        comb_resp = _mock_comb_response(200)

        lc_resp = _mock_leakcheck_response(0)
        with patch("requests.get", side_effect=[hibp_resp, comb_resp, lc_resp]):
            result = m.run(sample_assets)

        assert len(result.findings) == 2
        # HIBP: impact=1, COMB: impact=3 → score = 10 - 1 - 3 = 6
        assert result.score == 6

    def test_score_floor_at_zero(self, sample_assets):
        """大量 findings 時分數不應低於 0。"""
        m = DarkWebModule()
        all_breaches = [
            {"Name": f"Breach{i}", "Domain": "example.com", "PwnCount": i}
            for i in range(5)
        ]
        hibp_resp = _mock_hibp_response(all_breaches)
        comb_resp = _mock_comb_response(999)

        lc_resp = _mock_leakcheck_response(0)
        with patch("requests.get", side_effect=[hibp_resp, comb_resp, lc_resp]):
            result = m.run(sample_assets)

        assert result.score == 0

    # ------------------------------------------------------------------
    # 5. API 錯誤處理
    # ------------------------------------------------------------------

    def test_hibp_api_failure_comb_succeeds(self, sample_assets):
        """HIBP（core）失敗但 COMB（auxiliary）成功 → status=error（唯一 core 失敗）。
        但 COMB 仍正常產出 finding。"""
        m = DarkWebModule()
        comb_resp = _mock_comb_response(30)
        lc_resp = _mock_leakcheck_response(0)

        def side_effect(*args, **kwargs):
            url = args[0] if args else kwargs.get("url", "")
            if "haveibeenpwned" in url:
                raise Exception("connection timeout")
            if "leakcheck" in url:
                return lc_resp
            return comb_resp

        with patch("requests.get", side_effect=side_effect):
            result = m.run(sample_assets)

        # HIBP 是唯一 core source，失敗 → status=error
        assert result.status == "error"
        # 但 COMB（auxiliary）仍正常產出 finding → 細粒度韌性
        comb_findings = [f for f in result.findings if "外洩帳號密碼" in f.title]
        assert len(comb_findings) == 1
        src_by_id = {s.source_id: s for s in result.sources}
        assert src_by_id["hibp"].status == "failed"
        assert src_by_id["comb"].status == "success"

    def test_comb_api_failure_hibp_succeeds(self, sample_assets):
        """COMB（auxiliary）失敗但 HIBP（core）成功 → status=success。"""
        m = DarkWebModule()
        all_breaches = [
            {"Name": "TestBreach", "Domain": "example.com", "PwnCount": 50},
        ]
        hibp_resp = _mock_hibp_response(all_breaches)
        lc_resp = _mock_leakcheck_response(0)

        def side_effect(*args, **kwargs):
            url = args[0] if args else kwargs.get("url", "")
            if "proxynova" in url:
                raise Exception("connection refused")
            if "leakcheck" in url:
                return lc_resp
            return hibp_resp

        with patch("requests.get", side_effect=side_effect):
            result = m.run(sample_assets)

        # HIBP（core）成功 → status=success（auxiliary 失敗不影響，信心分數會反映）
        assert result.status == "success"
        hibp_findings = [f for f in result.findings if "Breach:" in f.title]
        assert len(hibp_findings) == 1
        src_by_id = {s.source_id: s for s in result.sources}
        assert src_by_id["hibp"].status == "success"
        assert src_by_id["comb"].status == "failed"

    def test_all_apis_fail(self, sample_assets):
        """三個 API 都失敗時，score 滿分（無扣分）但 status=error（所有 core 失敗）。"""
        m = DarkWebModule()

        with patch("requests.get", side_effect=Exception("network down")):
            result = m.run(sample_assets)

        assert result.status == "error"
        assert result.score == 10
        assert result.findings == []
        assert all(s.status == "failed" for s in result.sources)

    def test_hibp_non_200_status(self, sample_assets):
        """HIBP 回傳非 200 狀態碼時，應視為空清單。"""
        m = DarkWebModule()
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        comb_resp = _mock_comb_response(0)

        lc_resp = _mock_leakcheck_response(0)
        with patch("requests.get", side_effect=[mock_resp, comb_resp, lc_resp]):
            result = m.run(sample_assets)

        assert result.score == 10
        assert result.findings == []

    def test_comb_non_200_status(self, sample_assets):
        """COMB 回傳非 200 狀態碼時，應視為 0 筆。"""
        m = DarkWebModule()
        hibp_resp = _mock_hibp_response([])
        mock_resp = MagicMock()
        mock_resp.status_code = 500

        lc_resp = _mock_leakcheck_response(0)
        with patch("requests.get", side_effect=[hibp_resp, mock_resp, lc_resp]):
            result = m.run(sample_assets)

        assert result.score == 10
        assert result.findings == []

    # ------------------------------------------------------------------
    # 6. 內部方法單元測試
    # ------------------------------------------------------------------

    def test_check_hibp_public_filters_by_domain(self):
        """_check_hibp_public 回傳 (matching breaches, None)。"""
        m = DarkWebModule()
        all_breaches = [
            {"Name": "Match", "Domain": "target.com"},
            {"Name": "NoMatch", "Domain": "other.com"},
            {"Name": "Match2", "Domain": "TARGET.COM"},
        ]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = all_breaches

        with patch("requests.get", return_value=mock_resp):
            result, err = m._check_hibp_public("target.com")

        assert err is None
        assert len(result) == 2
        names = {b["Name"] for b in result}
        assert names == {"Match", "Match2"}

    def test_check_hibp_public_returns_empty_on_exception(self):
        """_check_hibp_public 內部例外應回傳 ([], error_str)。"""
        m = DarkWebModule()

        with patch("requests.get", side_effect=RuntimeError("unexpected")):
            result, err = m._check_hibp_public("example.com")

        assert result == []
        assert err is not None

    def test_check_credential_leaks_filters_by_email_suffix(self):
        """_check_credential_leaks 必須對 lines 做 email suffix 過濾，並帶出原始行。

        ProxyNova 回傳的 count 是 substring match 全集，含大量誤報；
        真實數量只能從 lines 中「email 結尾為 @domain」的筆數算出。
        matched_lines 必須保留原始 `email:password` 內容以供報告顯示。
        """
        m = DarkWebModule()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "count": 10000,
            "lines": [
                "alice@example.com:pw1",
                "bob@example.com:pw2",
                "not-related@other.com:pw3",
                "still-not@mail.ru:pw4",
            ],
        }

        with patch("requests.get", return_value=mock_resp):
            count, matched, err = m._check_credential_leaks("example.com")

        assert err is None
        assert count == 2
        assert matched == ["alice@example.com:pw1", "bob@example.com:pw2"]

    def test_check_credential_leaks_returns_zero_on_exception(self):
        """_check_credential_leaks 內部例外應回傳 (0, [], error_str)。"""
        m = DarkWebModule()

        with patch("requests.get", side_effect=RuntimeError("unexpected")):
            count, matched, err = m._check_credential_leaks("example.com")

        assert count == 0
        assert matched == []
        assert err is not None

    # ------------------------------------------------------------------
    # 7. ModuleResult 欄位完整性
    # ------------------------------------------------------------------

    def test_result_fields_present_on_success(self, sample_assets):
        """run() 回傳的 ModuleResult 必須包含所有必要欄位。"""
        m = DarkWebModule()
        hibp_resp = _mock_hibp_response([])
        comb_resp = _mock_comb_response(0)
        lc_resp = _mock_leakcheck_response(0)

        with patch("requests.get", side_effect=[hibp_resp, comb_resp, lc_resp]):
            result = m.run(sample_assets)

        assert result.module_id == "M6"
        assert result.module_name == "暗網帳號密碼外洩"
        assert result.max_score == 10
        assert isinstance(result.execution_time, float)
        assert result.execution_time >= 0.0
        assert isinstance(result.raw_data, dict)

    def test_result_fields_present_on_error(self, sample_assets):
        """API 全部失敗時 ModuleResult 亦必須包含所有必要欄位。"""
        m = DarkWebModule()

        with patch("requests.get", side_effect=Exception("all down")):
            result = m.run(sample_assets)

        assert result.module_id == "M6"
        assert result.module_name == "暗網帳號密碼外洩"
        assert result.max_score == 10
        assert isinstance(result.execution_time, float)

    # ------------------------------------------------------------------
    # 8. LeakCheck — 外洩資料庫查詢
    # ------------------------------------------------------------------

    def test_leakcheck_found_high(self, sample_assets):
        """LeakCheck found >100 時，severity=high，score_impact=2。"""
        m = DarkWebModule()
        hibp_resp = _mock_hibp_response([])
        comb_resp = _mock_comb_response(0)
        lc_resp = _mock_leakcheck_response(
            355, [{"name": "Stealer Logs", "date": ""}]
        )

        with patch("requests.get", side_effect=[hibp_resp, comb_resp, lc_resp]):
            result = m.run(sample_assets)

        lc_findings = [f for f in result.findings if "LeakCheck" in f.title]
        assert len(lc_findings) == 1
        assert lc_findings[0].severity == "high"
        assert lc_findings[0].score_impact == 2
        assert result.score == 8

    def test_leakcheck_found_medium(self, sample_assets):
        """LeakCheck found 11-100 時，severity=medium，score_impact=1。"""
        m = DarkWebModule()
        hibp_resp = _mock_hibp_response([])
        comb_resp = _mock_comb_response(0)
        lc_resp = _mock_leakcheck_response(
            50, [{"name": "Collection #1", "date": "2019"}]
        )

        with patch("requests.get", side_effect=[hibp_resp, comb_resp, lc_resp]):
            result = m.run(sample_assets)

        lc_findings = [f for f in result.findings if "LeakCheck" in f.title]
        assert len(lc_findings) == 1
        assert lc_findings[0].severity == "medium"
        assert lc_findings[0].score_impact == 1
        assert result.score == 9

    def test_leakcheck_found_low(self, sample_assets):
        """LeakCheck found 1-10 時，severity=low，score_impact=1。"""
        m = DarkWebModule()
        hibp_resp = _mock_hibp_response([])
        comb_resp = _mock_comb_response(0)
        lc_resp = _mock_leakcheck_response(
            5, [{"name": "Unknown DB", "date": ""}]
        )

        with patch("requests.get", side_effect=[hibp_resp, comb_resp, lc_resp]):
            result = m.run(sample_assets)

        lc_findings = [f for f in result.findings if "LeakCheck" in f.title]
        assert len(lc_findings) == 1
        assert lc_findings[0].severity == "low"
        assert lc_findings[0].score_impact == 1
        assert result.score == 9

    def test_leakcheck_not_found(self, sample_assets):
        """LeakCheck found=0 時，不應產生 finding。"""
        m = DarkWebModule()
        hibp_resp = _mock_hibp_response([])
        comb_resp = _mock_comb_response(0)
        lc_resp = _mock_leakcheck_response(0)

        with patch("requests.get", side_effect=[hibp_resp, comb_resp, lc_resp]):
            result = m.run(sample_assets)

        lc_findings = [f for f in result.findings if "LeakCheck" in f.title]
        assert len(lc_findings) == 0
        assert result.score == 10

    def test_leakcheck_error_independent(self, sample_assets):
        """LeakCheck 失敗時，不影響其他來源。"""
        m = DarkWebModule()
        hibp_resp = _mock_hibp_response([])
        comb_resp = _mock_comb_response(30)

        def side_effect(*args, **kwargs):
            url = args[0] if args else kwargs.get("url", "")
            if "leakcheck" in url:
                raise Exception("leakcheck down")
            if "proxynova" in url:
                return comb_resp
            return hibp_resp

        with patch("requests.get", side_effect=side_effect):
            result = m.run(sample_assets)

        assert result.status == "success"
        comb_findings = [f for f in result.findings if "外洩帳號密碼" in f.title]
        assert len(comb_findings) == 1
        lc_findings = [f for f in result.findings if "LeakCheck" in f.title]
        assert len(lc_findings) == 0

    def test_same_breach_not_double_counted(self, sample_assets):
        """同一 breach 名稱出現兩次時，只應計分一次。"""
        m = DarkWebModule()
        # HIBP 回傳同名 breach 兩次（例如 API 重複回傳）
        all_breaches = [
            {"Name": "DupBreach", "Domain": "example.com", "PwnCount": 100},
            {"Name": "DupBreach", "Domain": "Example.COM", "PwnCount": 100},
        ]
        hibp_resp = _mock_hibp_response(all_breaches)
        comb_resp = _mock_comb_response(0)
        lc_resp = _mock_leakcheck_response(0)

        with patch("requests.get", side_effect=[hibp_resp, comb_resp, lc_resp]):
            result = m.run(sample_assets)

        hibp_findings = [f for f in result.findings if "Breach:" in f.title]
        breach_titles = [f.title for f in hibp_findings]
        assert breach_titles.count("Breach: DupBreach") == 1, (
            "同名 breach 不應重複計分"
        )

    def test_all_three_sources_combined(self, sample_assets):
        """三來源同時有結果時，findings 合併，分數正確扣減。"""
        m = DarkWebModule()
        all_breaches = [
            {"Name": "BreachX", "Domain": "example.com", "PwnCount": 100},
        ]
        hibp_resp = _mock_hibp_response(all_breaches)
        comb_resp = _mock_comb_response(200)
        lc_resp = _mock_leakcheck_response(
            500, [{"name": "Stealer Logs", "date": ""}]
        )

        with patch("requests.get", side_effect=[hibp_resp, comb_resp, lc_resp]):
            result = m.run(sample_assets)

        assert len(result.findings) == 3
        # HIBP: impact=1, COMB: impact=3, LeakCheck: impact=2 → 10-1-3-2=4
        assert result.score == 4

    # ------------------------------------------------------------------
    # 9. LeakCheck 內部方法單元測試
    # ------------------------------------------------------------------

    def test_check_leakcheck_returns_count_and_sources(self):
        """_check_leakcheck 回傳 (count, sources, None)。"""
        m = DarkWebModule()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "success": True,
            "found": 42,
            "sources": [{"name": "DB1", "date": "2023"}],
        }

        with patch("requests.get", return_value=mock_resp):
            count, sources, err = m._check_leakcheck("example.com")

        assert err is None
        assert count == 42
        assert len(sources) == 1
        assert sources[0]["name"] == "DB1"

    def test_check_leakcheck_returns_zero_on_not_found(self):
        """_check_leakcheck found=0 → (0, [], None) 成功但無資料。"""
        m = DarkWebModule()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"success": True, "found": 0, "sources": []}

        with patch("requests.get", return_value=mock_resp):
            count, sources, err = m._check_leakcheck("example.com")

        assert err is None
        assert count == 0
        assert sources == []

    def test_check_leakcheck_returns_zero_on_exception(self):
        """_check_leakcheck 內部例外回傳 (0, [], error_str)。"""
        m = DarkWebModule()

        with patch("requests.get", side_effect=RuntimeError("unexpected")):
            count, sources, err = m._check_leakcheck("example.com")

        assert count == 0
        assert sources == []
        assert err is not None
