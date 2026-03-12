from __future__ import annotations
import os
import structlog
import requests
from cypulse.analysis.base import AnalysisModule
from cypulse.models import Assets, ModuleResult, Finding

logger = structlog.get_logger()


class IPReputationModule(AnalysisModule):
    def module_id(self) -> str:
        return "M2"

    def module_name(self) -> str:
        return "IP 信譽"

    def weight(self) -> float:
        return 0.15

    def max_score(self) -> int:
        return 15

    def run(self, assets: Assets) -> ModuleResult:
        import time
        start = time.time()
        findings: list[Finding] = []
        score = self.max_score()

        unique_ips = set()
        for asset in assets.subdomains:
            if asset.ip:
                unique_ips.add(asset.ip)

        api_key = os.environ.get("ABUSEIPDB_API_KEY", "")

        for ip in unique_ips:
            if api_key:
                result = self._check_abuseipdb(ip, api_key)
                if result:
                    findings.append(result)
                    score = max(0, score - result.score_impact)

        elapsed = time.time() - start
        return ModuleResult(
            module_id=self.module_id(),
            module_name=self.module_name(),
            score=score,
            max_score=self.max_score(),
            findings=findings,
            raw_data={},
            execution_time=elapsed,
            status="success" if api_key else "partial",
        )

    def _check_abuseipdb(self, ip: str, api_key: str) -> Finding | None:
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=10,
            )
            if resp.status_code != 200:
                return None
            data = resp.json().get("data", {})
            abuse_score = data.get("abuseConfidenceScore", 0)
            if abuse_score > 50:
                return Finding(
                    severity="high",
                    title=f"IP {ip} flagged on AbuseIPDB",
                    description=f"Abuse confidence: {abuse_score}%, reports: {data.get('totalReports', 0)}",
                    evidence=ip,
                    score_impact=10,
                )
            elif abuse_score > 20:
                return Finding(
                    severity="medium",
                    title=f"IP {ip} has abuse reports",
                    description=f"Abuse confidence: {abuse_score}%",
                    evidence=ip,
                    score_impact=5,
                )
        except Exception as e:
            logger.error("abuseipdb_check_failed", ip=ip, error=str(e))
        return None
