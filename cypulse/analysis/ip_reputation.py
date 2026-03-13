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

        for ip in unique_ips:
            # 來源 1: Shodan InternetDB（免費、不需 API key）
            shodan_findings = self._check_shodan_internetdb(ip)
            for f in shodan_findings:
                findings.append(f)
                score = max(0, score - f.score_impact)

            # 來源 2: GreyNoise Community（免費、不需 API key）
            greynoise_finding = self._check_greynoise(ip)
            if greynoise_finding:
                findings.append(greynoise_finding)
                score = max(0, score - greynoise_finding.score_impact)

            # 來源 3: AbuseIPDB（免費註冊、選填）
            api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
            if api_key:
                abuseipdb_finding = self._check_abuseipdb(ip, api_key)
                if abuseipdb_finding:
                    findings.append(abuseipdb_finding)
                    score = max(0, score - abuseipdb_finding.score_impact)

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

    def _check_shodan_internetdb(self, ip: str) -> list[Finding]:
        """Shodan InternetDB：查 IP 已知弱點與開放服務（免費、不需 API key）。"""
        findings: list[Finding] = []
        try:
            resp = requests.get(
                f"https://internetdb.shodan.io/{ip}",
                headers={"user-agent": "CyPulse"},
                timeout=10,
            )
            if resp.status_code != 200:
                return findings
            data = resp.json()
            vulns = data.get("vulns", [])
            if vulns:
                sev = "high" if len(vulns) > 5 else "medium"
                impact = min(5, len(vulns))
                findings.append(Finding(
                    severity=sev,
                    title=f"IP {ip} 存在 {len(vulns)} 個已知弱點",
                    description=(
                        f"Shodan InternetDB 回報 IP {ip} 存在"
                        f" {len(vulns)} 個 CVE 弱點: "
                        f"{', '.join(vulns[:5])}"
                        f"{'...' if len(vulns) > 5 else ''}"
                    ),
                    evidence=f"{ip}: {', '.join(vulns[:5])}",
                    score_impact=impact,
                ))
        except Exception as e:
            logger.error("shodan_internetdb_failed", ip=ip, error=str(e))
        return findings

    def _check_greynoise(self, ip: str) -> Finding | None:
        """GreyNoise Community API：查 IP 是否為已知惡意/掃描來源（免費、不需 API key）。"""
        try:
            resp = requests.get(
                f"https://api.greynoise.io/v3/community/{ip}",
                headers={"user-agent": "CyPulse"},
                timeout=10,
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            classification = data.get("classification", "unknown")
            noise = data.get("noise", False)
            name = data.get("name", "N/A")

            if classification == "malicious":
                return Finding(
                    severity="high",
                    title=f"IP {ip} 被 GreyNoise 標記為惡意",
                    description=(
                        f"GreyNoise 將 IP {ip} 分類為惡意來源"
                        f"（{name}）"
                    ),
                    evidence=f"{ip}: malicious ({name})",
                    score_impact=5,
                )
            elif noise:
                return Finding(
                    severity="medium",
                    title=f"IP {ip} 被偵測到掃描行為",
                    description=(
                        f"GreyNoise 偵測到 IP {ip} 存在網路掃描行為"
                        f"（{name}）"
                    ),
                    evidence=f"{ip}: noise ({name})",
                    score_impact=2,
                )
        except Exception as e:
            logger.error("greynoise_check_failed", ip=ip, error=str(e))
        return None

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
