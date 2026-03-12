from __future__ import annotations
import structlog
from cypulse.analysis.base import AnalysisModule
from cypulse.models import Assets, ModuleResult, Finding

logger = structlog.get_logger()


class EmailSecurityModule(AnalysisModule):
    def module_id(self) -> str:
        return "M5"

    def module_name(self) -> str:
        return "郵件安全"

    def weight(self) -> float:
        return 0.10

    def max_score(self) -> int:
        return 10

    def run(self, assets: Assets) -> ModuleResult:
        import time
        start = time.time()
        findings: list[Finding] = []
        score = self.max_score()

        try:
            import checkdmarc
        except ImportError as e:
            logger.error("checkdmarc_import_failed", error=str(e))
            return ModuleResult(
                module_id=self.module_id(),
                module_name=self.module_name(),
                score=0,
                max_score=self.max_score(),
                findings=[Finding(
                    severity="info",
                    title="checkdmarc unavailable",
                    description=f"checkdmarc 無法載入: {e}",
                )],
                raw_data={"error": str(e)},
                execution_time=time.time() - start,
                status="error",
            )

        try:
            result = checkdmarc.check_domains([assets.domain])

            if isinstance(result, list):
                result = result[0] if result else {}
            elif not isinstance(result, dict):
                result = {}

            # Check SPF
            spf = result.get("spf", {})
            if not spf.get("record"):
                findings.append(Finding(
                    severity="high",
                    title="No SPF record",
                    description=f"{assets.domain} 無 SPF 記錄",
                    evidence=assets.domain,
                    score_impact=4,
                ))
                score = max(0, score - 4)

            # Check DMARC
            dmarc = result.get("dmarc", {})
            if not dmarc.get("record"):
                findings.append(Finding(
                    severity="high",
                    title="No DMARC record",
                    description=f"{assets.domain} 無 DMARC 記錄",
                    evidence=assets.domain,
                    score_impact=6,
                ))
                score = max(0, score - 6)
            elif dmarc.get("policy") == "none":
                findings.append(Finding(
                    severity="medium",
                    title="DMARC policy is none",
                    description=f"{assets.domain} DMARC policy 設為 none，不具強制力",
                    evidence="p=none",
                    score_impact=3,
                ))
                score = max(0, score - 3)

        except Exception as e:
            logger.error("checkdmarc_failed", error=str(e))
            return ModuleResult(
                module_id=self.module_id(),
                module_name=self.module_name(),
                score=0,
                max_score=self.max_score(),
                findings=[Finding(
                    severity="info",
                    title="checkdmarc execution failed",
                    description=f"checkdmarc 執行失敗: {e}",
                )],
                raw_data={"error": str(e)},
                execution_time=time.time() - start,
                status="error",
            )

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
