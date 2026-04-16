from __future__ import annotations
import structlog
import requests
from cypulse.analysis.base import AnalysisModule, determine_status
from cypulse.models import Assets, ModuleResult, Finding, SourceStatus

logger = structlog.get_logger()


_SOURCE_DEFS = {
    "hibp":      ("core",      0.5),
    "comb":      ("auxiliary", 0.25),
    "leakcheck": ("auxiliary", 0.25),
}


def _classify_error(exc: BaseException) -> str:
    if isinstance(exc, requests.Timeout):
        return "timeout"
    if isinstance(exc, requests.RequestException):
        return f"http_error:{type(exc).__name__}"
    if isinstance(exc, (ValueError, KeyError)):
        return f"parse_error:{type(exc).__name__}"
    return f"unknown:{type(exc).__name__}"


class DarkWebModule(AnalysisModule):
    def module_id(self) -> str:
        return "M6"

    def module_name(self) -> str:
        return "暗網憑證外洩"

    def run(self, assets: Assets) -> ModuleResult:
        import time
        start = time.time()
        findings: list[Finding] = []
        score = self.max_score()
        source_errors: dict[str, str | None] = {sid: None for sid in _SOURCE_DEFS}

        # 來源 1: HIBP 公開清單 — 查域名是否為已知外洩事件來源
        hibp_breaches, hibp_err = self._check_hibp_public(assets.domain)
        source_errors["hibp"] = hibp_err
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
        leaked_count, comb_err = self._check_credential_leaks(assets.domain)
        source_errors["comb"] = comb_err
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
        leak_count, leak_sources, lc_err = self._check_leakcheck(assets.domain)
        source_errors["leakcheck"] = lc_err
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

        sources = [
            SourceStatus(
                source_id=sid,
                role=role,
                weight=weight,
                status="failed" if source_errors[sid] else "success",
                error=source_errors[sid],
            )
            for sid, (role, weight) in _SOURCE_DEFS.items()
        ]
        module_status = determine_status(sources)

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

    def _check_hibp_public(
        self, domain: str
    ) -> tuple[list[dict], str | None]:
        """HIBP 公開端點：回傳 (breaches, error)。"""
        try:
            resp = requests.get(
                "https://haveibeenpwned.com/api/v3/breaches",
                headers={"user-agent": "CyPulse"},
                timeout=15,
            )
            if resp.status_code != 200:
                return [], f"http_{resp.status_code}"
            breaches = [
                b for b in resp.json()
                if b.get("Domain", "").lower() == domain.lower()
            ]
            return breaches, None
        except Exception as e:
            logger.warning("hibp_public_failed", error=str(e))
            return [], _classify_error(e)

    def _check_credential_leaks(
        self, domain: str
    ) -> tuple[int, str | None]:
        """ProxyNova COMB：回傳 (leaked_count, error)。"""
        try:
            resp = requests.get(
                "https://api.proxynova.com/comb",
                params={"query": domain},
                headers={"user-agent": "CyPulse"},
                timeout=15,
            )
            if resp.status_code != 200:
                return 0, f"http_{resp.status_code}"
            return resp.json().get("count", 0), None
        except Exception as e:
            logger.warning("comb_check_failed", error=str(e))
            return 0, _classify_error(e)

    def _check_leakcheck(
        self, domain: str
    ) -> tuple[int, list[dict], str | None]:
        """LeakCheck Public API：回傳 (count, sources, error)。"""
        try:
            resp = requests.get(
                f"https://leakcheck.io/api/public?check={domain}",
                headers={"user-agent": "CyPulse"},
                timeout=15,
            )
            if resp.status_code != 200:
                return 0, [], f"http_{resp.status_code}"
            data = resp.json()
            if data.get("success") and data.get("found"):
                return (data.get("found", 0), data.get("sources", []), None)
            return 0, [], None
        except Exception as e:
            logger.warning("leakcheck_failed", error=str(e))
            return 0, [], _classify_error(e)
