from __future__ import annotations
import json
import os
import structlog
from cypulse.models import Assets, Findings, ModuleResult
from cypulse.analysis.web_security import WebSecurityModule
from cypulse.analysis.ip_reputation import IPReputationModule
from cypulse.analysis.network import NetworkSecurityModule
from cypulse.analysis.dns_security import DNSSecurityModule
from cypulse.analysis.email_security import EmailSecurityModule
from cypulse.analysis.darkweb import DarkWebModule
from cypulse.analysis.fake_domain import FakeDomainModule

logger = structlog.get_logger()

ALL_MODULES = [
    WebSecurityModule,
    IPReputationModule,
    NetworkSecurityModule,
    DNSSecurityModule,
    EmailSecurityModule,
    DarkWebModule,
    FakeDomainModule,
]


def run_analysis(assets: Assets, module_ids: list[str] | None = None) -> Findings:
    """Run all (or selected) analysis modules."""
    results: list[ModuleResult] = []

    for module_cls in ALL_MODULES:
        module = module_cls()
        if module_ids and module.module_id() not in module_ids:
            continue

        logger.info("analysis_start", module=module.module_id(), name=module.module_name())
        try:
            result = module.run(assets)
            results.append(result)
            logger.info(
                "analysis_complete",
                module=module.module_id(),
                score=result.score,
                max=result.max_score,
                findings=len(result.findings),
                time=f"{result.execution_time:.1f}s",
            )
        except Exception as e:
            logger.error("analysis_failed", module=module.module_id(), error=str(e))
            results.append(ModuleResult(
                module_id=module.module_id(),
                module_name=module.module_name(),
                score=0,
                max_score=module.max_score(),
                findings=[],
                raw_data={"error": str(e)},
                execution_time=0.0,
                status="error",
            ))

    return Findings(
        domain=assets.domain,
        timestamp=assets.timestamp,
        modules=results,
    )


def save_findings(findings: Findings, scan_dir: str) -> None:
    """Save findings to JSON files."""
    os.makedirs(scan_dir, exist_ok=True)

    # Save individual module results
    for module_result in findings.modules:
        path = os.path.join(scan_dir, f"module_{module_result.module_id}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(module_result.to_dict(), f, ensure_ascii=False, indent=2)

    # Save combined findings
    path = os.path.join(scan_dir, "findings.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(findings.to_dict(), f, ensure_ascii=False, indent=2)

    logger.info("findings_saved", scan_dir=scan_dir, modules=len(findings.modules))
