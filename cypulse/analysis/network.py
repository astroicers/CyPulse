from __future__ import annotations
import structlog
from cypulse.analysis.base import AnalysisModule
from cypulse.models import Assets, ModuleResult, Finding
from cypulse.utils.subprocess import run_cmd, check_tool

logger = structlog.get_logger()

HIGH_RISK_PORTS = {21, 23, 25, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017}


class NetworkSecurityModule(AnalysisModule):
    def module_id(self) -> str:
        return "M3"

    def module_name(self) -> str:
        return "網路服務安全"

    def weight(self) -> float:
        return 0.20

    def max_score(self) -> int:
        return 20

    def run(self, assets: Assets) -> ModuleResult:
        import time
        start = time.time()
        findings: list[Finding] = []
        score = self.max_score()

        # Check high-risk open ports from asset data
        for asset in assets.subdomains:
            for port in asset.ports:
                if port in HIGH_RISK_PORTS:
                    findings.append(Finding(
                        severity="high",
                        title=f"High-risk port {port} open",
                        description=f"{asset.subdomain}:{port} 為高風險服務端口",
                        evidence=f"{asset.subdomain}:{port}",
                        score_impact=5,
                    ))
                    score = max(0, score - 5)

        # Run nmap for service detection if available
        nmap_findings, failed_ips = self._run_nmap(assets)
        status = "success"
        if nmap_findings is None:
            status = "partial"
            findings.append(Finding(
                severity="info",
                title="nmap not installed",
                description="nmap 未安裝，CVE 弱點掃描未執行",
            ))
        else:
            for nf in nmap_findings:
                findings.append(nf)
                score = max(0, score - nf.score_impact)
            if failed_ips:
                status = "partial"
                findings.append(Finding(
                    severity="info",
                    title=f"nmap 掃描失敗 ({len(failed_ips)} IPs)",
                    description=f"以下 IP 掃描超時或失敗: {', '.join(failed_ips)}，結果可能不完整",
                ))

        elapsed = time.time() - start
        return ModuleResult(
            module_id=self.module_id(),
            module_name=self.module_name(),
            score=score,
            max_score=self.max_score(),
            findings=findings,
            raw_data={},
            execution_time=elapsed,
            status=status,
        )

    def _run_nmap(self, assets: Assets) -> tuple[list[Finding] | None, list[str]]:
        if not check_tool("nmap"):
            logger.warning("nmap_not_found")
            return None, []

        findings = []
        failed_ips = []
        seen_cves: set[str] = set()
        live_ips = set()
        for asset in assets.subdomains:
            if asset.ip:
                live_ips.add(asset.ip)

        for ip in list(live_ips)[:5]:  # Limit to 5 IPs
            try:
                result = run_cmd(
                    ["nmap", "-sV", "--script", "default", "-T4", "--top-ports", "20", ip],
                    timeout=120,
                    check=False,
                )
            except Exception:
                # 降級重試：減少 ports + 降低掃描速度
                logger.warning("nmap_fallback_retry", ip=ip)
                try:
                    result = run_cmd(
                        ["nmap", "-sV", "-T3", "--top-ports", "10", ip],
                        timeout=120,
                        check=False,
                    )
                except Exception as e:
                    logger.error("nmap_failed", ip=ip, error=str(e))
                    failed_ips.append(ip)
                    continue

            # Parse nmap output for CVEs（同一 CVE 只計一次）
            for line in result.stdout.splitlines():
                if "CVE-" in line:
                    cve = line.strip()
                    # 擷取 CVE ID（格式：CVE-YYYY-NNNNN）
                    import re
                    match = re.search(r"CVE-\d{4}-\d+", cve)
                    cve_id = match.group(0) if match else cve
                    if cve_id in seen_cves:
                        continue
                    seen_cves.add(cve_id)
                    findings.append(Finding(
                        severity="high",
                        title=f"CVE detected on {ip}",
                        description=cve,
                        evidence=f"{ip}: {cve}",
                        score_impact=5,
                    ))

        return findings, failed_ips
