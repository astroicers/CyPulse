"""EmailSecurityModule (M5) 單元測試。

涵蓋：
- 模組基本資訊（module_id、weight、max_score）
- checkdmarc 未安裝 → ImportError → score=0, status="error"
- 無 SPF 記錄 → severity="high", score_impact=4
- 無 DMARC 記錄 → severity="high", score_impact=6
- DMARC policy=none → severity="medium", score_impact=3
- SPF + DMARC 均存在且 policy 非 none → score=10
- checkdmarc.check_domains 拋出例外 → score=0, status="error"
"""
from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

from cypulse.models import Assets


# ---------------------------------------------------------------------------
# 輔助：建立假的 checkdmarc 模組，回傳可設定的 check_domains 回傳值
# ---------------------------------------------------------------------------

def _make_checkdmarc_mock(check_domains_return_value):
    """回傳一個行為如同 checkdmarc 模組的 MagicMock。"""
    mock_module = MagicMock(spec=ModuleType)
    mock_module.check_domains = MagicMock(return_value=check_domains_return_value)
    return mock_module


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_assets():
    return Assets(
        domain="example.com",
        timestamp="2026-03-13T000000",
        subdomains=[],
    )


# ---------------------------------------------------------------------------
# 測試類別
# ---------------------------------------------------------------------------

class TestEmailSecurityModule:
    """EmailSecurityModule (M5) 完整測試套件。"""

    # ------------------------------------------------------------------
    # 模組靜態資訊
    # ------------------------------------------------------------------

    def test_module_info(self):
        """module_id、weight、max_score 必須符合規格。"""
        # checkdmarc 不需要在 import 時存在；僅在 run() 內才 import
        from cypulse.analysis.email_security import EmailSecurityModule

        m = EmailSecurityModule()
        assert m.module_id() == "M5"
        # weight/max_score 從 WEIGHTS 取（ADR-005 調整為 0.08/8）
        assert m.weight() == pytest.approx(0.08)
        assert m.max_score() == 8

    def test_module_name(self):
        """module_name 應回傳非空字串。"""
        from cypulse.analysis.email_security import EmailSecurityModule

        m = EmailSecurityModule()
        assert isinstance(m.module_name(), str)
        assert len(m.module_name()) > 0

    # ------------------------------------------------------------------
    # checkdmarc 未安裝
    # ------------------------------------------------------------------

    def test_checkdmarc_not_installed(self, sample_assets):
        """當 checkdmarc 無法匯入時，應回傳 score=0 且 status='error'。"""
        from cypulse.analysis.email_security import EmailSecurityModule

        # 在 sys.modules 中把 checkdmarc 設為 None，迫使 import 拋出 ImportError
        with patch.dict(sys.modules, {"checkdmarc": None}):
            result = EmailSecurityModule().run(sample_assets)

        assert result.module_id == "M5"
        assert result.score == 0
        assert result.max_score == 8
        assert result.status == "error"
        # 應至少有一筆 finding 說明原因
        assert len(result.findings) >= 1
        titles = [f.title for f in result.findings]
        assert any("checkdmarc" in t.lower() for t in titles)

    # ------------------------------------------------------------------
    # 無 SPF 記錄
    # ------------------------------------------------------------------

    def test_no_spf_record(self, sample_assets):
        """無 SPF 記錄 → 扣 4 分，severity='high'，score=6。"""
        from cypulse.analysis.email_security import EmailSecurityModule

        check_domains_result = [
            {
                "spf": {},           # 無 record 欄位
                "dmarc": {
                    "record": "v=DMARC1; p=reject;",
                    "policy": "reject",
                },
            }
        ]
        mock_cd = _make_checkdmarc_mock(check_domains_result)

        with patch.dict(sys.modules, {"checkdmarc": mock_cd}):
            result = EmailSecurityModule().run(sample_assets)

        assert result.score == 4  # max_score 8 - SPF 扣 4
        assert result.status == "success"

        spf_findings = [f for f in result.findings if "SPF" in f.title]
        assert len(spf_findings) == 1
        assert spf_findings[0].severity == "high"
        assert spf_findings[0].score_impact == 4

    def test_no_spf_record_finding_evidence(self, sample_assets):
        """無 SPF 記錄時，finding evidence 應包含目標 domain。"""
        from cypulse.analysis.email_security import EmailSecurityModule

        check_domains_result = [
            {
                "spf": {},
                "dmarc": {"record": "v=DMARC1; p=reject;", "policy": "reject"},
            }
        ]
        mock_cd = _make_checkdmarc_mock(check_domains_result)

        with patch.dict(sys.modules, {"checkdmarc": mock_cd}):
            result = EmailSecurityModule().run(sample_assets)

        spf_finding = next(f for f in result.findings if "SPF" in f.title)
        assert spf_finding.evidence == "example.com"

    # ------------------------------------------------------------------
    # 無 DMARC 記錄
    # ------------------------------------------------------------------

    def test_no_dmarc_record(self, sample_assets):
        """無 DMARC 記錄 → 扣 6 分，severity='high'，score=4。"""
        from cypulse.analysis.email_security import EmailSecurityModule

        check_domains_result = [
            {
                "spf": {"record": "v=spf1 include:_spf.example.com ~all"},
                "dmarc": {},   # 無 record 欄位
            }
        ]
        mock_cd = _make_checkdmarc_mock(check_domains_result)

        with patch.dict(sys.modules, {"checkdmarc": mock_cd}):
            result = EmailSecurityModule().run(sample_assets)

        assert result.score == 2  # max_score 8 - DMARC 扣 6
        assert result.status == "success"

        dmarc_findings = [f for f in result.findings if "DMARC" in f.title]
        assert len(dmarc_findings) == 1
        assert dmarc_findings[0].severity == "high"
        assert dmarc_findings[0].score_impact == 6

    def test_no_dmarc_record_finding_evidence(self, sample_assets):
        """無 DMARC 記錄時，finding evidence 應包含目標 domain。"""
        from cypulse.analysis.email_security import EmailSecurityModule

        check_domains_result = [
            {
                "spf": {"record": "v=spf1 include:_spf.example.com ~all"},
                "dmarc": {},
            }
        ]
        mock_cd = _make_checkdmarc_mock(check_domains_result)

        with patch.dict(sys.modules, {"checkdmarc": mock_cd}):
            result = EmailSecurityModule().run(sample_assets)

        dmarc_finding = next(f for f in result.findings if "DMARC" in f.title)
        assert dmarc_finding.evidence == "example.com"

    # ------------------------------------------------------------------
    # DMARC policy=none
    # ------------------------------------------------------------------

    def test_dmarc_policy_none(self, sample_assets):
        """DMARC policy=none → 扣 3 分，severity='medium'，score=7。"""
        from cypulse.analysis.email_security import EmailSecurityModule

        check_domains_result = [
            {
                "spf": {"record": "v=spf1 include:_spf.example.com ~all"},
                "dmarc": {
                    "record": "v=DMARC1; p=none;",
                    "policy": "none",
                },
            }
        ]
        mock_cd = _make_checkdmarc_mock(check_domains_result)

        with patch.dict(sys.modules, {"checkdmarc": mock_cd}):
            result = EmailSecurityModule().run(sample_assets)

        assert result.score == 5  # max_score 8 - policy=none 扣 3
        assert result.status == "success"

        policy_findings = [f for f in result.findings if "policy" in f.title.lower()]
        assert len(policy_findings) == 1
        assert policy_findings[0].severity == "medium"
        assert policy_findings[0].score_impact == 3

    def test_dmarc_policy_none_finding_evidence(self, sample_assets):
        """DMARC policy=none 的 finding evidence 應為 'p=none'。"""
        from cypulse.analysis.email_security import EmailSecurityModule

        check_domains_result = [
            {
                "spf": {"record": "v=spf1 include:_spf.example.com ~all"},
                "dmarc": {"record": "v=DMARC1; p=none;", "policy": "none"},
            }
        ]
        mock_cd = _make_checkdmarc_mock(check_domains_result)

        with patch.dict(sys.modules, {"checkdmarc": mock_cd}):
            result = EmailSecurityModule().run(sample_assets)

        policy_finding = next(
            f for f in result.findings if "policy" in f.title.lower()
        )
        assert policy_finding.evidence == "p=none"

    # ------------------------------------------------------------------
    # SPF + DMARC 均正確設定
    # ------------------------------------------------------------------

    def test_all_records_present(self, sample_assets):
        """SPF 與 DMARC（policy 非 none）均存在 → score=max_score=8，無 findings。"""
        from cypulse.analysis.email_security import EmailSecurityModule

        check_domains_result = [
            {
                "spf": {"record": "v=spf1 include:_spf.example.com ~all"},
                "dmarc": {
                    "record": "v=DMARC1; p=reject;",
                    "policy": "reject",
                },
            }
        ]
        mock_cd = _make_checkdmarc_mock(check_domains_result)

        with patch.dict(sys.modules, {"checkdmarc": mock_cd}):
            result = EmailSecurityModule().run(sample_assets)

        assert result.score == 8
        assert result.max_score == 8
        assert result.status == "success"
        assert result.findings == []

    def test_all_records_present_quarantine_policy(self, sample_assets):
        """DMARC policy=quarantine 視為有效保護，score=max_score=8。"""
        from cypulse.analysis.email_security import EmailSecurityModule

        check_domains_result = [
            {
                "spf": {"record": "v=spf1 include:_spf.example.com ~all"},
                "dmarc": {
                    "record": "v=DMARC1; p=quarantine;",
                    "policy": "quarantine",
                },
            }
        ]
        mock_cd = _make_checkdmarc_mock(check_domains_result)

        with patch.dict(sys.modules, {"checkdmarc": mock_cd}):
            result = EmailSecurityModule().run(sample_assets)

        assert result.score == 8
        assert result.status == "success"

    # ------------------------------------------------------------------
    # 同時缺少 SPF 與 DMARC → 最壞情況
    # ------------------------------------------------------------------

    def test_no_spf_and_no_dmarc(self, sample_assets):
        """SPF(-4) + DMARC(-6) 均缺失 → score=0，兩筆 findings。"""
        from cypulse.analysis.email_security import EmailSecurityModule

        check_domains_result = [{"spf": {}, "dmarc": {}}]
        mock_cd = _make_checkdmarc_mock(check_domains_result)

        with patch.dict(sys.modules, {"checkdmarc": mock_cd}):
            result = EmailSecurityModule().run(sample_assets)

        assert result.score == 0
        assert result.status == "success"
        assert len(result.findings) == 2

        severities = {f.severity for f in result.findings}
        assert severities == {"high"}

    # ------------------------------------------------------------------
    # checkdmarc.check_domains 拋出例外
    # ------------------------------------------------------------------

    def test_checkdmarc_exception(self, sample_assets):
        """check_domains 拋出 RuntimeError → score=0, status='error'。"""
        from cypulse.analysis.email_security import EmailSecurityModule

        mock_cd = MagicMock(spec=ModuleType)
        mock_cd.check_domains = MagicMock(
            side_effect=RuntimeError("DNS lookup failed")
        )

        with patch.dict(sys.modules, {"checkdmarc": mock_cd}):
            result = EmailSecurityModule().run(sample_assets)

        assert result.score == 0
        assert result.max_score == 8
        assert result.status == "error"
        assert len(result.findings) >= 1

    def test_checkdmarc_connection_error(self, sample_assets):
        """check_domains 拋出 ConnectionError → score=0, status='error'。"""
        from cypulse.analysis.email_security import EmailSecurityModule

        mock_cd = MagicMock(spec=ModuleType)
        mock_cd.check_domains = MagicMock(
            side_effect=ConnectionError("network unreachable")
        )

        with patch.dict(sys.modules, {"checkdmarc": mock_cd}):
            result = EmailSecurityModule().run(sample_assets)

        assert result.score == 0
        assert result.status == "error"

    # ------------------------------------------------------------------
    # 結果結構完整性
    # ------------------------------------------------------------------

    def test_result_has_execution_time(self, sample_assets):
        """ModuleResult 必須包含 execution_time 且 >= 0。"""
        from cypulse.analysis.email_security import EmailSecurityModule

        check_domains_result = [
            {
                "spf": {"record": "v=spf1 include:_spf.example.com ~all"},
                "dmarc": {"record": "v=DMARC1; p=reject;", "policy": "reject"},
            }
        ]
        mock_cd = _make_checkdmarc_mock(check_domains_result)

        with patch.dict(sys.modules, {"checkdmarc": mock_cd}):
            result = EmailSecurityModule().run(sample_assets)

        assert result.execution_time >= 0

    def test_result_module_id_and_name_consistent(self, sample_assets):
        """無論執行結果如何，module_id 與 module_name 應始終一致。"""
        from cypulse.analysis.email_security import EmailSecurityModule

        check_domains_result = [
            {
                "spf": {"record": "v=spf1 include:_spf.example.com ~all"},
                "dmarc": {"record": "v=DMARC1; p=reject;", "policy": "reject"},
            }
        ]
        mock_cd = _make_checkdmarc_mock(check_domains_result)

        m = EmailSecurityModule()
        with patch.dict(sys.modules, {"checkdmarc": mock_cd}):
            result = m.run(sample_assets)

        assert result.module_id == m.module_id()
        assert result.module_name == m.module_name()

    def test_score_never_below_zero(self, sample_assets):
        """score 在任何情況下都不能為負數。"""
        from cypulse.analysis.email_security import EmailSecurityModule

        # SPF(-4) + DMARC(-6) = -10 → max(0, ...) → 0
        check_domains_result = [{"spf": {}, "dmarc": {}}]
        mock_cd = _make_checkdmarc_mock(check_domains_result)

        with patch.dict(sys.modules, {"checkdmarc": mock_cd}):
            result = EmailSecurityModule().run(sample_assets)

        assert result.score >= 0

    # ------------------------------------------------------------------
    # check_domains 回傳空 list
    # ------------------------------------------------------------------

    def test_check_domains_returns_empty_list(self, sample_assets):
        """check_domains 回傳空 list → result 視為空 dict，不應崩潰。"""
        from cypulse.analysis.email_security import EmailSecurityModule

        mock_cd = _make_checkdmarc_mock([])  # 空 list

        with patch.dict(sys.modules, {"checkdmarc": mock_cd}):
            result = EmailSecurityModule().run(sample_assets)

        # 無記錄 → spf={}, dmarc={} → 扣 4+6=10 → score=0
        assert result.score == 0
        assert result.status == "success"

    # ------------------------------------------------------------------
    # check_domains 回傳非 list/dict 的奇異值
    # ------------------------------------------------------------------

    def test_check_domains_returns_non_dict_non_list(self, sample_assets):
        """check_domains 回傳字串等非預期型別 → 應視為空結果，不崩潰。"""
        from cypulse.analysis.email_security import EmailSecurityModule

        mock_cd = _make_checkdmarc_mock("unexpected_string")

        with patch.dict(sys.modules, {"checkdmarc": mock_cd}):
            result = EmailSecurityModule().run(sample_assets)

        # result 被規範化為 {} → spf/dmarc 均缺失
        assert result.score == 0
        assert result.status == "success"
