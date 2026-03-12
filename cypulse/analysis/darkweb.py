from __future__ import annotations
import os
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

        api_key = os.environ.get("HIBP_API_KEY", "")
        if api_key:
            breaches = self._check_hibp(assets.domain, api_key)
            for breach in breaches:
                impact = min(3, len(breaches))  # Max -3 per breach, cap at -10 total
                findings.append(Finding(
                    severity="high",
                    title=f"Breach: {breach.get('Name', 'Unknown')}",
                    description=f"Domain {assets.domain} 出現在 {breach.get('Name', '')} 資料外洩事件中",
                    evidence=breach.get("Name", ""),
                    score_impact=impact,
                ))
                score = max(0, score - impact)
        else:
            logger.warning("hibp_no_api_key", module=self.module_id())

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

    def _check_hibp(self, domain: str, api_key: str) -> list[dict]:
        try:
            resp = requests.get(
                "https://haveibeenpwned.com/api/v3/breaches",
                headers={"hibp-api-key": api_key, "user-agent": "CyPulse"},
                params={"domain": domain},
                timeout=10,
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            logger.error("hibp_failed", error=str(e))
        return []
