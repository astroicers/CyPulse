from __future__ import annotations
import structlog
from cypulse.analysis.base import AnalysisModule
from cypulse.models import Assets, ModuleResult, Finding

logger = structlog.get_logger()


class FakeDomainModule(AnalysisModule):
    def module_id(self) -> str:
        return "M7"

    def module_name(self) -> str:
        return "偽冒域名偵測"

    def weight(self) -> float:
        return 0.05

    def max_score(self) -> int:
        return 5

    def run(self, assets: Assets) -> ModuleResult:
        import time
        start = time.time()
        findings: list[Finding] = []
        score = self.max_score()

        try:
            fake_domains = self._run_dnstwist(assets.domain)
            resolved = [d for d in fake_domains if d.get("dns_a") or d.get("dns_aaaa")]

            for domain_info in resolved[:5]:  # Cap at 5 findings
                findings.append(Finding(
                    severity="medium",
                    title=f"Suspicious domain: {domain_info.get('domain', '')}",
                    description=f"偽冒域名 {domain_info.get('domain', '')} 已有 DNS 解析 ({domain_info.get('fuzzer', '')})",
                    evidence=domain_info.get("domain", ""),
                    score_impact=1,
                ))
                score = max(0, score - 1)

        except Exception as e:
            logger.error("dnstwist_failed", error=str(e))

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

    def _run_dnstwist(self, domain: str) -> list[dict]:
        try:
            import dnstwist
            scanner = dnstwist.DomainFuzz(domain)
            scanner.generate()
            results = scanner.domains
            return results if isinstance(results, list) else []
        except ImportError:
            logger.warning("dnstwist_not_installed")
            return []
        except Exception as e:
            logger.error("dnstwist_error", error=str(e))
            return []
