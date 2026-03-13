import subprocess
from unittest.mock import MagicMock, patch

import pytest

from cypulse.analysis.dns_security import DNSSecurityModule
from cypulse.models import Asset, Assets


# ---------------------------------------------------------------------------
# 輔助工廠
# ---------------------------------------------------------------------------

def _make_assets(domain: str = "example.com") -> Assets:
    return Assets(
        domain=domain,
        timestamp="2026-03-13T000000",
        subdomains=[
            Asset(subdomain=f"www.{domain}", ip="93.184.216.34"),
        ],
    )


def _completed(stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess:
    """回傳一個模擬的 CompletedProcess 物件。"""
    result = MagicMock(spec=subprocess.CompletedProcess)
    result.stdout = stdout
    result.returncode = returncode
    return result


# ---------------------------------------------------------------------------
# 測試類別
# ---------------------------------------------------------------------------

class TestDNSSecurityModule:
    """M4 DNSSecurityModule 單元測試。"""

    # ------------------------------------------------------------------
    # 模組基本資訊
    # ------------------------------------------------------------------

    def test_module_info(self):
        """驗證模組識別碼、權重與最高分設定正確。"""
        m = DNSSecurityModule()
        assert m.module_id() == "M4"
        assert m.module_name() == "DNS 安全"
        assert m.weight() == 0.15
        assert m.max_score() == 15

    # ------------------------------------------------------------------
    # DNSSEC 未啟用
    # ------------------------------------------------------------------

    @patch("cypulse.analysis.dns_security.check_tool", return_value=True)
    @patch("cypulse.analysis.dns_security.run_cmd")
    def test_dnssec_missing(self, mock_run_cmd, mock_check_tool):
        """dig 回傳空字串時，應產生 medium 等級 finding 且扣 5 分。"""
        # dig 回傳空字串（DNSSEC 未設定）
        # dnsrecon 回傳無 Zone Transfer 字樣
        mock_run_cmd.side_effect = [
            _completed(stdout=""),                          # dig DNSKEY → 空
            _completed(stdout="No zone transfer found"),    # dnsrecon axfr
        ]

        m = DNSSecurityModule()
        result = m.run(_make_assets())

        assert result.module_id == "M4"
        assert result.score == 10          # 15 - 5
        assert result.status == "success"

        titles = [f.title for f in result.findings]
        assert "DNSSEC not enabled" in titles

        dnssec_finding = next(f for f in result.findings if f.title == "DNSSEC not enabled")
        assert dnssec_finding.severity == "medium"
        assert dnssec_finding.score_impact == 5

    # ------------------------------------------------------------------
    # Zone Transfer 允許
    # ------------------------------------------------------------------

    @patch("cypulse.analysis.dns_security.check_tool", return_value=True)
    @patch("cypulse.analysis.dns_security.run_cmd")
    def test_zone_transfer_allowed(self, mock_run_cmd, mock_check_tool):
        """dnsrecon 回報 Zone Transfer 成功時，應產生 critical finding 且扣 10 分。"""
        mock_run_cmd.side_effect = [
            _completed(stdout="example.com. 3600 IN DNSKEY 257 3 8 ..."),  # dig → 有 DNSSEC
            _completed(stdout="Zone Transfer was successful!!"),             # dnsrecon → 允許
        ]

        m = DNSSecurityModule()
        result = m.run(_make_assets())

        assert result.score == 5           # 15 - 10
        assert result.status == "success"

        zt_finding = next(
            (f for f in result.findings if f.title == "Zone Transfer allowed"),
            None,
        )
        assert zt_finding is not None
        assert zt_finding.severity == "critical"
        assert zt_finding.score_impact == 10
        assert zt_finding.evidence == "example.com"

    # ------------------------------------------------------------------
    # dnsrecon 未安裝
    # ------------------------------------------------------------------

    @patch("cypulse.analysis.dns_security.check_tool", return_value=False)
    @patch("cypulse.analysis.dns_security.run_cmd")
    def test_dnsrecon_not_installed(self, mock_run_cmd, mock_check_tool):
        """dnsrecon 未安裝時，狀態應為 partial 並產生 info finding；不呼叫 dnsrecon。"""
        # 只有 dig 會被呼叫（DNSSEC 存在）
        mock_run_cmd.return_value = _completed(
            stdout="example.com. 3600 IN DNSKEY 257 3 8 AwEAA..."
        )

        m = DNSSecurityModule()
        result = m.run(_make_assets())

        assert result.status == "partial"
        assert result.score == 15          # DNSSEC 正常，Zone Transfer 未扣分

        info_finding = next(
            (f for f in result.findings if f.title == "dnsrecon not installed"),
            None,
        )
        assert info_finding is not None
        assert info_finding.severity == "info"

        # dnsrecon 指令不應被執行
        for call in mock_run_cmd.call_args_list:
            cmd = call.args[0] if call.args else call.kwargs.get("cmd", [])
            assert "dnsrecon" not in cmd[0]

    # ------------------------------------------------------------------
    # 全部安全（DNSSEC 啟用 + Zone Transfer 禁止）
    # ------------------------------------------------------------------

    @patch("cypulse.analysis.dns_security.check_tool", return_value=True)
    @patch("cypulse.analysis.dns_security.run_cmd")
    def test_all_secure(self, mock_run_cmd, mock_check_tool):
        """DNSSEC 啟用且無 Zone Transfer 時，滿分 15 且無非 info 等級 finding。"""
        mock_run_cmd.side_effect = [
            _completed(stdout="example.com. 3600 IN DNSKEY 257 3 8 AwEAA..."),  # dig
            _completed(stdout="Trying NS servers"),                               # dnsrecon
        ]

        m = DNSSecurityModule()
        result = m.run(_make_assets())

        assert result.score == 15
        assert result.status == "success"
        assert result.max_score == 15
        assert result.module_id == "M4"

        # 不應有任何扣分 finding
        penalty_findings = [
            f for f in result.findings if f.severity not in ("info",)
        ]
        assert penalty_findings == []

    # ------------------------------------------------------------------
    # dig 例外
    # ------------------------------------------------------------------

    @patch("cypulse.analysis.dns_security.check_tool", return_value=True)
    @patch("cypulse.analysis.dns_security.run_cmd")
    def test_dig_exception(self, mock_run_cmd, mock_check_tool):
        """dig 拋出例外時，_check_dnssec 應回傳 False（視同未啟用 DNSSEC）。"""
        # 第一次呼叫（dig）拋出例外；第二次（dnsrecon）正常
        mock_run_cmd.side_effect = [
            Exception("dig: command not found"),
            _completed(stdout="No zone transfer found"),
        ]

        m = DNSSecurityModule()
        result = m.run(_make_assets())

        # dig 失敗 → DNSSEC 視為未啟用 → 扣 5 分
        assert result.score == 10

        dnssec_finding = next(
            (f for f in result.findings if f.title == "DNSSEC not enabled"),
            None,
        )
        assert dnssec_finding is not None
        assert dnssec_finding.severity == "medium"

    # ------------------------------------------------------------------
    # 同時 DNSSEC 缺失 + Zone Transfer 允許（最壞情況）
    # ------------------------------------------------------------------

    @patch("cypulse.analysis.dns_security.check_tool", return_value=True)
    @patch("cypulse.analysis.dns_security.run_cmd")
    def test_both_failures_score_floored_at_zero(self, mock_run_cmd, mock_check_tool):
        """DNSSEC 缺失（-5）加上 Zone Transfer（-10）總扣 15 分，分數不得低於 0。"""
        mock_run_cmd.side_effect = [
            _completed(stdout=""),                                    # dig → 無 DNSSEC
            _completed(stdout="Zone Transfer was successful!!"),      # dnsrecon → 允許
        ]

        m = DNSSecurityModule()
        result = m.run(_make_assets())

        assert result.score == 0
        assert result.status == "success"
        assert len(result.findings) == 2

        severities = {f.severity for f in result.findings}
        assert "medium" in severities
        assert "critical" in severities
