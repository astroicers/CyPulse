from __future__ import annotations
import os
import structlog
import requests
from cypulse.analysis.base import AnalysisModule, determine_status
from cypulse.utils.http import http_get
from cypulse.models import Assets, ModuleResult, Finding, SourceStatus

logger = structlog.get_logger()


# 來源定義：id → (role, weight)。weight 總和應為 1.0。
_SOURCE_DEFS = {
    "shodan":    ("core",      0.35),
    "abuseipdb": ("core",      0.35),
    "greynoise": ("auxiliary", 0.15),
    "ip_api":    ("auxiliary", 0.15),
}


def _classify_error(exc: BaseException) -> str:
    from cypulse.utils.http import SourceUnavailable
    if isinstance(exc, SourceUnavailable):
        return exc.reason
    if isinstance(exc, requests.Timeout):
        return "timeout"
    if isinstance(exc, requests.RequestException):
        return f"http_error:{type(exc).__name__}"
    if isinstance(exc, (ValueError, KeyError)):
        return f"parse_error:{type(exc).__name__}"
    return f"unknown:{type(exc).__name__}"


class IPReputationModule(AnalysisModule):
    def module_id(self) -> str:
        return "M2"

    def module_name(self) -> str:
        return "IP 信譽"

    def run(self, assets: Assets) -> ModuleResult:
        import time
        start = time.time()
        findings: list[Finding] = []
        score = self.max_score()

        unique_ips = {a.ip for a in assets.subdomains if a.ip}

        # 各 source 的聚合狀態：只要對任一 IP 失敗就標 failed（悲觀）
        source_state: dict[str, dict] = {
            sid: {"success_ips": 0, "failure": None}
            for sid in _SOURCE_DEFS
        }
        abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY", "")

        for ip in unique_ips:
            ip_candidates: dict[str, Finding] = {}

            # Shodan
            sh_findings, sh_err = self._check_shodan_internetdb(ip)
            self._update_source_state(source_state, "shodan", sh_err)
            for f in sh_findings:
                ip_candidates[f"{ip}:shodan"] = f

            # GreyNoise
            gn_finding, gn_err = self._check_greynoise(ip)
            self._update_source_state(source_state, "greynoise", gn_err)
            if gn_finding:
                ip_candidates[f"{ip}:greynoise"] = gn_finding

            # AbuseIPDB（僅當 API key 存在）
            if abuseipdb_key:
                ab_finding, ab_err = self._check_abuseipdb(ip, abuseipdb_key)
                self._update_source_state(source_state, "abuseipdb", ab_err)
                if ab_finding:
                    ip_candidates[f"{ip}:abuseipdb"] = ab_finding

            # IP-API
            ia_finding, ia_err = self._check_ipapi(ip)
            self._update_source_state(source_state, "ip_api", ia_err)
            if ia_finding:
                ip_candidates[f"{ip}:ip_api"] = ia_finding

            for f in ip_candidates.values():
                findings.append(f)
                score = max(0, score - f.score_impact)

        # 彙整 sources 狀態
        sources: list[SourceStatus] = []
        for sid, (role, weight) in _SOURCE_DEFS.items():
            state = source_state[sid]
            if sid == "abuseipdb" and not abuseipdb_key:
                status = "skipped"
                err = "no_api_key"
            elif not unique_ips:
                status = "skipped"
                err = "no_ips_to_check"
            elif state["failure"]:
                status = "failed"
                err = state["failure"]
            else:
                status = "success"
                err = None
            sources.append(SourceStatus(
                source_id=sid, role=role, weight=weight,
                status=status, error=err,
            ))

        module_status = determine_status(sources)
        # 若所有來源都 skipped（沒 IP），維持 success（無資料可查並非失敗）
        if module_status == "error" and all(s.status == "skipped" for s in sources):
            module_status = "success"

        elapsed = time.time() - start
        return ModuleResult(
            module_id=self.module_id(),
            module_name=self.module_name(),
            score=score,
            max_score=self.max_score(),
            findings=findings,
            raw_data={},
            execution_time=elapsed,
            status=module_status,
            sources=sources,
        )

    @staticmethod
    def _update_source_state(state: dict, sid: str, err: str | None) -> None:
        if err is None:
            state[sid]["success_ips"] += 1
        elif state[sid]["failure"] is None:
            state[sid]["failure"] = err

    def _check_shodan_internetdb(
        self, ip: str
    ) -> tuple[list[Finding], str | None]:
        """回傳 (findings, error)。error=None 表示成功。"""
        findings: list[Finding] = []
        try:
            resp = http_get(
                f"https://internetdb.shodan.io/{ip}",
                headers={"user-agent": "CyPulse"},
                timeout=10,
            )
            if resp.status_code == 404:
                return findings, None  # IP 未知 = 成功查詢無命中
            if resp.status_code != 200:
                return findings, f"http_{resp.status_code}"
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
            return findings, None
        except Exception as e:
            logger.warning("shodan_internetdb_failed", ip=ip, error=str(e))
            return findings, _classify_error(e)

    def _check_greynoise(
        self, ip: str
    ) -> tuple[Finding | None, str | None]:
        try:
            resp = http_get(
                f"https://api.greynoise.io/v3/community/{ip}",
                headers={"user-agent": "CyPulse"},
                timeout=10,
            )
            if resp.status_code == 404:
                return None, None
            if resp.status_code != 200:
                return None, f"http_{resp.status_code}"
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
                ), None
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
                ), None
            return None, None
        except Exception as e:
            logger.warning("greynoise_check_failed", ip=ip, error=str(e))
            return None, _classify_error(e)

    _SUSPICIOUS_ORG_KEYWORDS = frozenset([
        "tor", "vpn", "anonymous", "proxy", "bulletproof",
        "m247", "njalla", "frantech", "hostkey",
    ])

    def _check_ipapi(
        self, ip: str
    ) -> tuple[Finding | None, str | None]:
        try:
            resp = http_get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,country,org,as,isp"},
                headers={"user-agent": "CyPulse"},
                timeout=10,
            )
            if resp.status_code != 200:
                return None, f"http_{resp.status_code}"
            data = resp.json()
            if data.get("status") != "success":
                # ip-api 的 fail 視為「此 IP 無資料」，非 API 掛
                return None, None
            org = data.get("org", "").lower()
            isp = data.get("isp", "").lower()
            combined = f"{org} {isp}"
            if any(kw in combined for kw in self._SUSPICIOUS_ORG_KEYWORDS):
                return Finding(
                    severity="medium",
                    title=f"Suspicious ASN: {data.get('as', 'unknown')}",
                    description=(
                        f"IP {ip} 屬於可疑 ASN/組織: {data.get('org', '')} "
                        f"（{data.get('country', '')}），"
                        f"可能為 Tor 出口或匿名代理服務"
                    ),
                    evidence=f"{ip}: {data.get('org', '')} / {data.get('as', '')}",
                    score_impact=2,
                ), None
            return None, None
        except Exception as e:
            logger.warning("ipapi_check_failed", ip=ip, error=str(e))
            return None, _classify_error(e)

    def _check_abuseipdb(
        self, ip: str, api_key: str
    ) -> tuple[Finding | None, str | None]:
        try:
            resp = http_get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=10,
            )
            if resp.status_code != 200:
                return None, f"http_{resp.status_code}"
            data = resp.json().get("data", {})
            abuse_score = data.get("abuseConfidenceScore", 0)
            if abuse_score > 50:
                return Finding(
                    severity="high",
                    title=f"IP {ip} flagged on AbuseIPDB",
                    description=(
                        f"Abuse confidence: {abuse_score}%, "
                        f"reports: {data.get('totalReports', 0)}"
                    ),
                    evidence=ip,
                    score_impact=10,
                ), None
            elif abuse_score > 20:
                return Finding(
                    severity="medium",
                    title=f"IP {ip} has abuse reports",
                    description=f"Abuse confidence: {abuse_score}%",
                    evidence=ip,
                    score_impact=5,
                ), None
            return None, None
        except Exception as e:
            logger.warning("abuseipdb_check_failed", ip=ip, error=str(e))
            return None, _classify_error(e)
