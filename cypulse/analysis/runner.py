from __future__ import annotations
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import structlog
from cypulse.models import Assets, Findings, ModuleResult
from cypulse.analysis.web_security import WebSecurityModule
from cypulse.analysis.ip_reputation import IPReputationModule
from cypulse.analysis.network import NetworkSecurityModule
from cypulse.analysis.dns_security import DNSSecurityModule
from cypulse.analysis.email_security import EmailSecurityModule
from cypulse.analysis.darkweb import DarkWebModule
from cypulse.analysis.fake_domain import FakeDomainModule
from cypulse.analysis.cloud_exposure import CloudExposureModule
from cypulse.utils.io import safe_write_json

logger = structlog.get_logger()

ALL_MODULES = [
    WebSecurityModule,
    IPReputationModule,
    NetworkSecurityModule,
    DNSSecurityModule,
    EmailSecurityModule,
    DarkWebModule,
    FakeDomainModule,
    CloudExposureModule,
]


def _run_single_module(module, assets: Assets) -> ModuleResult:
    """執行單一分析模組（供平行化使用）。"""
    logger.info("analysis_start", module=module.module_id(), name=module.module_name())
    try:
        result = module.run(assets)
        logger.info(
            "analysis_complete",
            module=module.module_id(),
            score=result.score,
            max=result.max_score,
            findings=len(result.findings),
            time=f"{result.execution_time:.1f}s",
        )
        return result
    except Exception as e:
        logger.error("analysis_failed", module=module.module_id(), error=str(e))
        return ModuleResult(
            module_id=module.module_id(),
            module_name=module.module_name(),
            score=0,
            max_score=module.max_score(),
            findings=[],
            raw_data={"error": str(e)},
            execution_time=0.0,
            status="error",
        )


def run_analysis(assets: Assets, module_ids: list[str] | None = None) -> Findings:
    """Run all (or selected) analysis modules in parallel."""
    modules = []
    for module_cls in ALL_MODULES:
        module = module_cls()
        if module_ids and module.module_id() not in module_ids:
            continue
        modules.append(module)

    results: list[ModuleResult] = []
    with ThreadPoolExecutor(max_workers=len(modules)) as executor:
        future_to_module = {
            executor.submit(_run_single_module, m, assets): m
            for m in modules
        }
        for future in as_completed(future_to_module):
            results.append(future.result())

    # 按 module_id 排序確保輸出一致
    results.sort(key=lambda r: r.module_id)

    return Findings(
        domain=assets.domain,
        timestamp=assets.timestamp,
        modules=results,
    )


def save_findings(findings: Findings, scan_dir: str) -> None:
    """Save findings to JSON files (atomic write)."""
    for module_result in findings.modules:
        path = os.path.join(scan_dir, f"module_{module_result.module_id}.json")
        safe_write_json(path, module_result.to_dict())

    path = os.path.join(scan_dir, "findings.json")
    safe_write_json(path, findings.to_dict())

    logger.info("findings_saved", scan_dir=scan_dir, modules=len(findings.modules))
