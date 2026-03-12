from __future__ import annotations
import structlog
from cypulse.analysis.base import AnalysisModule
from cypulse.models import Assets, ModuleResult, Finding
from cypulse.utils.subprocess import run_cmd, check_tool

logger = structlog.get_logger()


class DNSSecurityModule(AnalysisModule):
    def module_id(self) -> str:
        return "M4"

    def module_name(self) -> str:
        return "DNS 安全"

    def weight(self) -> float:
        return 0.15

    def max_score(self) -> int:
        return 15

    def run(self, assets: Assets) -> ModuleResult:
        import time
        start = time.time()
        findings: list[Finding] = []
        score = self.max_score()

        # Check DNSSEC
        dnssec_ok = self._check_dnssec(assets.domain)
        if not dnssec_ok:
            findings.append(Finding(
                severity="medium",
                title="DNSSEC not enabled",
                description=f"{assets.domain} 未啟用 DNSSEC",
                evidence=assets.domain,
                score_impact=5,
            ))
            score = max(0, score - 5)

        # Check zone transfer
        zone_transfer = self._check_zone_transfer(assets.domain)
        if zone_transfer:
            findings.append(Finding(
                severity="critical",
                title="Zone Transfer allowed",
                description=f"{assets.domain} 允許 DNS Zone Transfer",
                evidence=assets.domain,
                score_impact=10,
            ))
            score = max(0, score - 10)

        elapsed = time.time() - start
        return ModuleResult(
            module_id=self.module_id(),
            module_name=self.module_name(),
            score=score,
            max_score=self.max_score(),
            findings=findings,
            raw_data={},
            execution_time=elapsed,
            status="success",
        )

    def _check_dnssec(self, domain: str) -> bool:
        try:
            result = run_cmd(
                ["dig", "+short", domain, "DNSKEY"],
                timeout=10, check=False,
            )
            return bool(result.stdout.strip())
        except Exception:
            return False

    def _check_zone_transfer(self, domain: str) -> bool:
        if not check_tool("dnsrecon"):
            return False
        try:
            result = run_cmd(
                ["dnsrecon", "-d", domain, "-t", "axfr"],
                timeout=30, check=False,
            )
            return "Zone Transfer was successful" in result.stdout
        except Exception:
            return False
