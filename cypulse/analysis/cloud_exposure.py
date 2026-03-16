from __future__ import annotations
import json
import os
import tempfile
import structlog
from cypulse.analysis.base import AnalysisModule
from cypulse.models import Assets, ModuleResult, Finding
from cypulse.utils.subprocess import run_cmd, check_tool

logger = structlog.get_logger()


def _derive_bucket_names(domain: str) -> list[str]:
    prefix = domain.replace(".", "-")
    return [
        prefix,
        f"www-{prefix}",
        f"media-{prefix}",
        f"assets-{prefix}",
        f"cdn-{prefix}",
        f"backup-{prefix}",
        f"static-{prefix}",
    ]


class CloudExposureModule(AnalysisModule):
    def module_id(self) -> str:
        return "M8"

    def module_name(self) -> str:
        return "雲端資產暴露"

    def weight(self) -> float:
        return 0.04

    def max_score(self) -> int:
        return 4

    def run(self, assets: Assets) -> ModuleResult:
        import time
        start = time.time()
        findings: list[Finding] = []
        score = self.max_score()
        status = "success"

        if not check_tool("s3scanner"):
            logger.warning("s3scanner_not_found")
            findings.append(Finding(
                severity="info",
                title="s3scanner not installed",
                description="s3scanner 未安裝，雲端 bucket 暴露掃描未執行",
            ))
            return ModuleResult(
                module_id=self.module_id(), module_name=self.module_name(),
                score=score, max_score=self.max_score(),
                findings=findings, raw_data={},
                execution_time=time.time() - start, status="partial",
            )

        bucket_names = _derive_bucket_names(assets.domain)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(bucket_names))
            tmpfile = f.name

        result = None
        try:
            result = run_cmd(
                ["s3scanner", "scan", "--buckets-file", tmpfile, "--out-format", "json"],
                timeout=60,
                check=False,
            )
        except Exception as e:
            logger.warning("s3scanner_failed", error=str(e))
            status = "partial"
        finally:
            os.unlink(tmpfile)

        if result:
            for line in result.stdout.splitlines():
                try:
                    item = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if not item.get("exists"):
                    continue
                bucket = item.get("bucket", "unknown")
                if item.get("public_read") or item.get("public_write"):
                    sev = "critical" if item.get("public_write") else "high"
                    impact = 3 if item.get("public_write") else 2
                    perm = "公開可寫" if item.get("public_write") else "公開可讀"
                    findings.append(Finding(
                        severity=sev,
                        title=f"Public Cloud Bucket: {bucket}",
                        description=f"雲端 bucket {bucket} 設為{perm}，可能包含敏感資料",
                        evidence=f"bucket: {bucket}, region: {item.get('region', 'unknown')}",
                        score_impact=impact,
                    ))
                    score = max(0, score - impact)

        elapsed = time.time() - start
        return ModuleResult(
            module_id=self.module_id(), module_name=self.module_name(),
            score=score, max_score=self.max_score(),
            findings=findings, raw_data={},
            execution_time=elapsed, status=status,
        )
