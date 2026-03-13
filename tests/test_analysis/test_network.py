from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from cypulse.analysis.network import HIGH_RISK_PORTS, NetworkSecurityModule
from cypulse.models import Asset, Assets


class TestNetworkSecurityModule:
    """NetworkSecurityModule (M3) 單元測試。"""

    # ------------------------------------------------------------------
    # 模組基本資訊
    # ------------------------------------------------------------------

    def test_module_info(self):
        """確認模組 ID、權重、滿分皆符合規格。"""
        m = NetworkSecurityModule()
        assert m.module_id() == "M3"
        assert m.weight() == 0.20
        assert m.max_score() == 20

    # ------------------------------------------------------------------
    # 高風險端口偵測
    # ------------------------------------------------------------------

    def test_high_risk_port(self, sample_assets):
        """資產含 HIGH_RISK_PORTS 中的端口時，應產生 severity=high、score_impact=5 的 Finding。"""
        # 在 sample_asset 中插入一個高風險端口（22 不在清單，3306 在）
        sample_assets.subdomains[0].ports = [443, 3306]

        m = NetworkSecurityModule()
        with patch("cypulse.analysis.network.check_tool", return_value=False):
            result = m.run(sample_assets)

        high_findings = [f for f in result.findings if f.severity == "high"]
        assert len(high_findings) >= 1, "應偵測到至少一個高風險端口 Finding"

        port_finding = next(f for f in high_findings if "3306" in f.title)
        assert port_finding.score_impact == 5
        assert result.score == 20 - 5  # 一個高風險端口扣 5 分

    def test_high_risk_port_deducts_score(self):
        """開放多個高風險端口時，分數應累積扣減且不低於 0。"""
        # 建立含 5 個高風險端口的資產（最多扣 25 分，但上限為 0）
        risky_ports = list(HIGH_RISK_PORTS)[:5]
        assets = Assets(
            domain="example.com",
            timestamp="2026-03-13T000000",
            subdomains=[
                Asset(subdomain="host.example.com", ip="1.2.3.4", ports=risky_ports),
            ],
        )
        m = NetworkSecurityModule()
        with patch("cypulse.analysis.network.check_tool", return_value=False):
            result = m.run(assets)

        assert result.score == 0, "累計扣減應使分數不低於 0"
        high_findings = [f for f in result.findings if f.severity == "high"]
        assert len(high_findings) == 5

    def test_safe_ports_no_high_risk_finding(self, sample_assets):
        """資產僅開放 80/443 等安全端口時，不應產生 high severity Finding。"""
        sample_assets.subdomains[0].ports = [80, 443]

        m = NetworkSecurityModule()
        with patch("cypulse.analysis.network.check_tool", return_value=False):
            result = m.run(sample_assets)

        high_findings = [f for f in result.findings if f.severity == "high"]
        assert len(high_findings) == 0

    # ------------------------------------------------------------------
    # nmap 未安裝
    # ------------------------------------------------------------------

    def test_nmap_not_installed(self, sample_assets):
        """nmap 未安裝時，status 應為 'partial'，並附帶 severity=info 的 Finding。"""
        m = NetworkSecurityModule()
        with patch("cypulse.analysis.network.check_tool", return_value=False):
            result = m.run(sample_assets)

        assert result.status == "partial"
        info_findings = [f for f in result.findings if f.severity == "info"]
        assert len(info_findings) >= 1, "應有至少一個 info Finding 說明 nmap 未安裝"
        titles = [f.title for f in info_findings]
        assert any("nmap" in t.lower() for t in titles)

    # ------------------------------------------------------------------
    # nmap 偵測到 CVE
    # ------------------------------------------------------------------

    def test_nmap_finds_cve(self, sample_assets):
        """nmap 輸出含 CVE 識別碼時，應產生 severity=high、score_impact=5 的 Finding。"""
        mock_result = MagicMock(spec=subprocess.CompletedProcess)
        mock_result.stdout = (
            "Starting Nmap 7.94\n"
            "| CVE-2021-44228: Apache Log4j RCE\n"
            "Nmap done.\n"
        )

        m = NetworkSecurityModule()
        with patch("cypulse.analysis.network.check_tool", return_value=True), \
             patch("cypulse.analysis.network.run_cmd", return_value=mock_result):
            result = m.run(sample_assets)

        assert result.status == "success"
        cve_findings = [
            f for f in result.findings
            if f.severity == "high" and "CVE" in f.title
        ]
        assert len(cve_findings) >= 1, "應至少偵測到一個 CVE Finding"
        assert cve_findings[0].score_impact == 5
        assert "CVE-2021-44228" in cve_findings[0].description

    def test_nmap_no_cve(self, sample_assets):
        """nmap 輸出不含 CVE 時，不應產生任何 CVE Finding，分數應為滿分。"""
        mock_result = MagicMock(spec=subprocess.CompletedProcess)
        mock_result.stdout = (
            "Starting Nmap 7.94\n"
            "80/tcp  open  http\n"
            "443/tcp open  https\n"
            "Nmap done.\n"
        )

        m = NetworkSecurityModule()
        with patch("cypulse.analysis.network.check_tool", return_value=True), \
             patch("cypulse.analysis.network.run_cmd", return_value=mock_result):
            result = m.run(sample_assets)

        cve_findings = [f for f in result.findings if "CVE" in f.title]
        assert len(cve_findings) == 0
        assert result.score == m.max_score()

    # ------------------------------------------------------------------
    # 無子網域
    # ------------------------------------------------------------------

    def test_no_subdomains(self):
        """無任何子網域時，分數應為滿分 20，且無 high severity Finding。"""
        assets = Assets(
            domain="example.com",
            timestamp="2026-03-13T000000",
            subdomains=[],
        )
        m = NetworkSecurityModule()
        with patch("cypulse.analysis.network.check_tool", return_value=True), \
             patch("cypulse.analysis.network.run_cmd") as mock_run:
            result = m.run(assets)

        # 沒有子網域，nmap 不應被呼叫
        mock_run.assert_not_called()
        assert result.score == 20
        high_findings = [f for f in result.findings if f.severity == "high"]
        assert len(high_findings) == 0

    # ------------------------------------------------------------------
    # nmap 拋出例外
    # ------------------------------------------------------------------

    def test_nmap_exception(self, sample_assets):
        """nmap 執行時拋出例外，模組不應崩潰，應記錄錯誤並繼續回傳結果。"""
        m = NetworkSecurityModule()
        with patch("cypulse.analysis.network.check_tool", return_value=True), \
             patch(
                 "cypulse.analysis.network.run_cmd",
                 side_effect=Exception("nmap process error"),
             ):
            # 不應拋出例外
            result = m.run(sample_assets)

        # 模組應正常完成，nmap 全部失敗時 status 為 partial
        assert result is not None
        assert result.module_id == "M3"
        # nmap 例外導致所有 IP 失敗，status 應為 partial
        assert result.status == "partial"

    def test_nmap_timeout_exception(self, sample_assets):
        """nmap subprocess.TimeoutExpired 亦應被捕獲，不崩潰。"""
        m = NetworkSecurityModule()
        with patch("cypulse.analysis.network.check_tool", return_value=True), \
             patch(
                 "cypulse.analysis.network.run_cmd",
                 side_effect=subprocess.TimeoutExpired(cmd="nmap", timeout=60),
             ):
            result = m.run(sample_assets)

        assert result is not None
        assert result.module_id == "M3"

    # ------------------------------------------------------------------
    # ModuleResult 結構完整性
    # ------------------------------------------------------------------

    def test_result_structure(self, sample_assets):
        """回傳的 ModuleResult 應包含所有必要欄位且型別正確。"""
        m = NetworkSecurityModule()
        with patch("cypulse.analysis.network.check_tool", return_value=False):
            result = m.run(sample_assets)

        assert result.module_id == "M3"
        assert result.module_name == "網路服務安全"
        assert isinstance(result.score, int)
        assert result.max_score == 20
        assert 0 <= result.score <= result.max_score
        assert isinstance(result.findings, list)
        assert isinstance(result.execution_time, float)
        assert result.execution_time >= 0.0

    # ------------------------------------------------------------------
    # HIGH_RISK_PORTS 集合完整性
    # ------------------------------------------------------------------

    def test_high_risk_ports_set(self):
        """確認 HIGH_RISK_PORTS 包含規格中指定的所有端口。"""
        required = {21, 23, 25, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017}
        assert required == HIGH_RISK_PORTS
