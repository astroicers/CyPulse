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

        # 統計每種 header 缺失的子網域
        http_assets = [a for a in assets.subdomains if a.http_status]
        header_missing: dict[str, list[str]] = {h: [] for h in CRITICAL_HEADERS}

        for asset in http_assets:
            headers = asset.security_headers or {}
            normalized = {k.lower(): v for k, v in headers.items()}
            for header in CRITICAL_HEADERS:
                if not normalized.get(header) and not normalized.get(header.replace("-", "_")):
                    header_missing[header].append(asset.subdomain)

        # 每種 header 產生一筆彙總 finding
        for header, missing_subs in header_missing.items():
            if not missing_subs:
                continue
            count = len(missing_subs)
            deduction = min(count, 5)  # 每種 header 最多扣 5 分
            preview = ", ".join(missing_subs[:5])
            suffix = f" 等 {count} 個" if count > 5 else ""
            findings.append(Finding(
                severity="medium",
                title=f"Missing {header}",
                description=f"{count} 個子網域缺少 {header} header（{preview}{suffix}）",
                evidence=", ".join(missing_subs[:10]),
                score_impact=deduction,
            ))
            score = max(0, score - deduction)

        # TLS check (per subdomain)
        for asset in http_assets:
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

        # Run testssl.sh if available
        testssl_findings = self._run_testssl(assets)
        if testssl_findings is None:
            status = "partial"
            findings.append(Finding(
                severity="info",
                title="testssl.sh not installed",
                description="testssl.sh 未安裝，TLS 深度掃描未執行",
            ))
        else:
            for tf in testssl_findings:
                findings.append(tf)
                score = max(0, score - tf.score_impact)

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

    def _run_testssl(self, assets: Assets) -> list[Finding] | None:
        """使用 testssl.sh 深度掃描 TLS 設定（憑證過期、弱 cipher、HSTS 等）。"""
        if not check_tool("testssl.sh"):
            logger.warning("testssl_not_found")
            return None

        findings = []
        https_assets = [
            a for a in assets.subdomains
            if a.http_status and a.ports and 443 in a.ports
        ][:3]

        SEVERITY_MAP = {
            "CRITICAL": ("critical", 5),
            "HIGH":     ("high",     3),
            "MEDIUM":   ("medium",   2),
            "LOW":      ("low",      1),
            "OK":       None,
            "INFO":     None,
            "WARN":     ("low",      1),
        }

        for asset in https_assets:
            host = f"{asset.subdomain}:443"
            try:
                result = run_cmd(
                    ["testssl.sh", "--jsonfile", "-", "--quiet", "--color", "0", host],
                    timeout=60,
                    check=False,
                )
            except Exception as e:
                logger.warning("testssl_failed", host=host, error=str(e))
                continue

            try:
                items = json.loads(result.stdout)
            except (json.JSONDecodeError, ValueError):
                continue

            for item in items:
                sev_raw = item.get("severity", "").upper()
                mapped = SEVERITY_MAP.get(sev_raw)
                if not mapped:
                    continue
                severity, impact = mapped
                findings.append(Finding(
                    severity=severity,
                    title=f"TLS Issue: {item.get('id', 'unknown')}",
                    description=f"{asset.subdomain}: {item.get('finding', '')}",
                    evidence=f"{host}: {item.get('id', '')}",
                    score_impact=impact,
                ))

        return findings

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
            import tempfile
            import os
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write("\n".join(live_hosts))
                hosts_file = f.name
            try:
                nuclei_cmd = [
                    "nuclei", "-l", hosts_file, "-json", "-silent",
                    "-tags", "misconfig,exposure,tech",
                ]
                max_attempts = 2
                result = None
                for attempt in range(max_attempts):
                    try:
                        result = sp.run(
                            nuclei_cmd,
                            capture_output=True, text=True, timeout=300,
                        )
                        break
                    except Exception as e:
                        if attempt < max_attempts - 1:
                            logger.warning("nuclei_retry", attempt=attempt + 1, error=str(e))
                            import time
                            time.sleep(5)
                        else:
                            logger.error("nuclei_failed", error=str(e))

                if result:
                    for line in result.stdout.strip().splitlines():
                        if not line.strip():
                            continue
                        try:
                            data = json.loads(line)
                            sev = data.get("info", {}).get("severity", "info")
                            impact_map = {
                                "critical": 8, "high": 5,
                                "medium": 3, "low": 1, "info": 0,
                            }
                            impact = impact_map.get(sev, 0)
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
