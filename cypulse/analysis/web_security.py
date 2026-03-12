from __future__ import annotations
import json
import structlog
from cypulse.analysis.base import AnalysisModule
from cypulse.models import Assets, ModuleResult, Finding
from cypulse.utils.subprocess import run_cmd, check_tool

logger = structlog.get_logger()

CRITICAL_HEADERS = ["strict-transport-security", "content-security-policy", "x-frame-options"]


class WebSecurityModule(AnalysisModule):
    def module_id(self) -> str:
        return "M1"

    def module_name(self) -> str:
        return "網站服務安全"

    def weight(self) -> float:
        return 0.25

    def max_score(self) -> int:
        return 25

    def run(self, assets: Assets) -> ModuleResult:
        import time
        start = time.time()
        findings: list[Finding] = []
        score = self.max_score()

        # Check security headers from asset data
        for asset in assets.subdomains:
            if not asset.http_status:
                continue
            headers = asset.security_headers or {}
            for header in CRITICAL_HEADERS:
                normalized = {k.lower(): v for k, v in headers.items()}
                if not normalized.get(header) and not normalized.get(header.replace("-", "_")):
                    findings.append(Finding(
                        severity="medium",
                        title=f"Missing {header}",
                        description=f"{asset.subdomain} 缺少 {header} header",
                        evidence=asset.subdomain,
                        score_impact=3,
                    ))
                    score = max(0, score - 3)

            # TLS check
            if asset.tls_version and asset.tls_version < "TLSv1.2":
                findings.append(Finding(
                    severity="high",
                    title="Weak TLS Version",
                    description=f"{asset.subdomain} 使用 {asset.tls_version}",
                    evidence=f"{asset.subdomain}: {asset.tls_version}",
                    score_impact=10,
                ))
                score = max(0, score - 10)

        # Run nuclei if available
        nuclei_findings = self._run_nuclei(assets)
        status = "success"
        if nuclei_findings is None:
            status = "partial"
            findings.append(Finding(
                severity="info",
                title="nuclei not installed",
                description="nuclei 未安裝，弱點掃描未執行",
            ))
        else:
            for nf in nuclei_findings:
                findings.append(nf)
                score = max(0, score - nf.score_impact)

        elapsed = time.time() - start
        return ModuleResult(
            module_id=self.module_id(),
            module_name=self.module_name(),
            score=score,
            max_score=self.max_score(),
            findings=findings,
            raw_data={},
            execution_time=elapsed,
            status=status,
        )

    def _run_nuclei(self, assets: Assets) -> list[Finding] | None:
        if not check_tool("nuclei"):
            logger.warning("nuclei_not_found")
            return None

        live_hosts = [a.subdomain for a in assets.subdomains if a.http_status]
        if not live_hosts:
            return []

        findings = []
        try:
            import subprocess as sp
            import tempfile, os
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write("\n".join(live_hosts))
                hosts_file = f.name
            try:
                result = sp.run(
                    ["nuclei", "-l", hosts_file, "-json", "-silent",
                     "-tags", "misconfig,exposure,tech"],
                    capture_output=True, text=True, timeout=300,
                )
                for line in result.stdout.strip().splitlines():
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        sev = data.get("info", {}).get("severity", "info")
                        impact = {"critical": 8, "high": 5, "medium": 3, "low": 1, "info": 0}.get(sev, 0)
                        findings.append(Finding(
                            severity=sev,
                            title=data.get("info", {}).get("name", "Unknown"),
                            description=data.get("info", {}).get("description", ""),
                            evidence=data.get("matched-at", ""),
                            score_impact=impact,
                        ))
                    except json.JSONDecodeError:
                        continue
            finally:
                os.unlink(hosts_file)
        except Exception as e:
            logger.error("nuclei_failed", error=str(e))

        return findings
