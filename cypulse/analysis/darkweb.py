from __future__ import annotations
import structlog
import requests
from cypulse.analysis.base import AnalysisModule
from cypulse.models import Assets, ModuleResult, Finding

logger = structlog.get_logger()


class DarkWebModule(AnalysisModule):
    def module_id(self) -> str:
        return "M6"

    def module_name(self) -> str:
        return "暗網憑證外洩"

    def weight(self) -> float:
        return 0.10

    def max_score(self) -> int:
        return 10

    def run(self, assets: Assets) -> ModuleResult:
        import time
        start = time.time()
        findings: list[Finding] = []
        score = self.max_score()

        # 來源 1: HIBP 公開清單 — 查域名是否為已知外洩事件來源
        hibp_breaches = self._check_hibp_public(assets.domain)
        seen_breach_names: set[str] = set()
        for breach in hibp_breaches:
            breach_name = breach.get("Name", "Unknown")
            if breach_name in seen_breach_names:
                continue
            seen_breach_names.add(breach_name)
            impact = min(3, len(hibp_breaches))
            findings.append(Finding(
                severity="high",
                title=f"Breach: {breach_name}",
                description=(
                    f"Domain {assets.domain} 曾發生資料外洩事件: "
                    f"{breach_name}，"
                    f"影響 {breach.get('PwnCount', '未知')} 筆資料"
                ),
                evidence=breach_name,
                score_impact=impact,
            ))
            score = max(0, score - impact)

        # 來源 2: ProxyNova COMB — 查域名 email 是否在外洩資料庫中
        leaked_count = self._check_credential_leaks(assets.domain)
        if leaked_count > 0:
            if leaked_count > 100:
                sev, impact = "high", 3
            elif leaked_count > 10:
                sev, impact = "medium", 2
            else:
                sev, impact = "low", 1
            findings.append(Finding(
                severity=sev,
                title=f"發現 {leaked_count} 筆外洩憑證",
                description=(
                    f"在公開外洩資料庫中發現 {leaked_count} 筆"
                    f"與 {assets.domain} 相關的憑證記錄"
                ),
                evidence=f"{assets.domain}: {leaked_count} credentials",
                score_impact=impact,
            ))
            score = max(0, score - impact)

        # 來源 3: LeakCheck — 查域名是否出現在外洩資料庫
        leak_count, leak_sources = self._check_leakcheck(assets.domain)
        if leak_count > 0:
            source_names = ", ".join(
                s.get("name", "Unknown") for s in leak_sources[:5]
            )
            if leak_count > 100:
                sev, impact = "high", 2
            elif leak_count > 10:
                sev, impact = "medium", 1
            else:
                sev, impact = "low", 1
            findings.append(Finding(
                severity=sev,
                title=f"LeakCheck: 發現 {leak_count} 筆外洩記錄",
                description=(
                    f"LeakCheck 資料庫中發現 {leak_count} 筆"
                    f"與 {assets.domain} 相關的外洩記錄"
                    f"（來源: {source_names}）"
                ),
                evidence=f"{assets.domain}: {leak_count} records via LeakCheck",
                score_impact=impact,
            ))
            score = max(0, score - impact)

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

    def _check_hibp_public(self, domain: str) -> list[dict]:
        """HIBP 公開端點：查域名是否為已知外洩事件來源（免費、不需 API key）。"""
        try:
            resp = requests.get(
                "https://haveibeenpwned.com/api/v3/breaches",
                headers={"user-agent": "CyPulse"},
                timeout=15,
            )
            if resp.status_code == 200:
                return [
                    b for b in resp.json()
                    if b.get("Domain", "").lower() == domain.lower()
                ]
        except Exception as e:
            logger.error("hibp_public_failed", error=str(e))
        return []

    def _check_credential_leaks(self, domain: str) -> int:
        """ProxyNova COMB：查域名相關的外洩憑證數量（免費、不需 API key）。"""
        try:
            resp = requests.get(
                "https://api.proxynova.com/comb",
                params={"query": domain},
                headers={"user-agent": "CyPulse"},
                timeout=15,
            )
            if resp.status_code == 200:
                return resp.json().get("count", 0)
        except Exception as e:
            logger.error("comb_check_failed", error=str(e))
        return 0

    def _check_leakcheck(self, domain: str) -> tuple[int, list[dict]]:
        """LeakCheck Public API：查域名是否出現在外洩資料庫（免費、不需 API key）。"""
        try:
            resp = requests.get(
                f"https://leakcheck.io/api/public?check={domain}",
                headers={"user-agent": "CyPulse"},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success") and data.get("found"):
                    return (data.get("found", 0), data.get("sources", []))
        except Exception as e:
            logger.error("leakcheck_failed", error=str(e))
        return (0, [])
