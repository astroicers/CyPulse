from __future__ import annotations
import json
import os
import structlog
from cypulse.models import DiffItem, DiffReport
from cypulse.utils.io import safe_write_json

logger = structlog.get_logger()


class DiffSchemaError(Exception):
    """新版 scan_dir 的 JSON 不符合預期 schema（代碼 bug，應 raise）。

    舊版 scan_dir schema 不符 不會 raise，而是 compare() 回傳含警示 alert
    的空 DiffReport（讓 cron 排程不被舊資料拖垮）。
    """


# 必要 key 定義（驗證 schema）
_REQUIRED_KEYS = {
    "score.json": {"total", "dimensions"},
    "findings.json": {"domain", "modules"},
}


def _validate_schema(filename: str, data: dict, *, label: str) -> list[str]:
    """檢查 data 是否含 _REQUIRED_KEYS 定義的必要欄位。

    Returns: 缺失的欄位 list；空 list 表示通過。
    """
    required = _REQUIRED_KEYS.get(filename, set())
    return sorted(required - set(data.keys()))


class DiffEngine:

    def compare(self, old_dir: str, new_dir: str) -> DiffReport:
        old_score = self._load_json(os.path.join(old_dir, "score.json"))
        new_score = self._load_json(os.path.join(new_dir, "score.json"))
        old_findings = self._load_json(os.path.join(old_dir, "findings.json"))
        new_findings = self._load_json(os.path.join(new_dir, "findings.json"))

        # 驗證新 scan schema：缺鍵代表代碼 bug，raise
        for fname, data in (("score.json", new_score), ("findings.json", new_findings)):
            missing = _validate_schema(fname, data, label="new")
            if missing:
                raise DiffSchemaError(
                    f"new scan {fname} 缺少必要欄位: {missing}"
                )

        # 驗證舊 scan schema：缺鍵代表舊版 / 損毀，回 alert（不 raise）
        old_missing = []
        for fname, data in (("score.json", old_score), ("findings.json", old_findings)):
            missing = _validate_schema(fname, data, label="old")
            if missing:
                old_missing.append(f"{fname}: {missing}")

        if old_missing:
            old_scan_ts = os.path.basename(old_dir)
            new_scan_ts = os.path.basename(new_dir)
            logger.warning(
                "diff_schema_incompatible",
                old=old_scan_ts, missing=old_missing,
            )
            return DiffReport(
                old_scan=old_scan_ts,
                new_scan=new_scan_ts,
                score_change=0,
                new_findings=[],
                resolved_findings=[],
                alerts=[
                    f"舊掃描 {old_scan_ts} schema 不相容（{', '.join(old_missing)}），"
                    f"無法比對；建議重新掃描以建立新版基準"
                ],
            )

        score_change = new_score.get("total", 0) - old_score.get("total", 0)

        # Compare findings
        old_set = self._extract_finding_keys(old_findings)
        new_set = self._extract_finding_keys(new_findings)

        new_items = []
        for key in new_set - old_set:
            sev, title = key
            new_items.append(DiffItem(
                category="new_finding",
                severity=sev,
                description=title,
            ))

        resolved_items = []
        for key in old_set - new_set:
            sev, title = key
            resolved_items.append(DiffItem(
                category="resolved",
                severity=sev,
                description=title,
            ))

        # Generate alerts
        alerts = []
        if score_change < -10:
            alerts.append(f"Score dropped by {abs(score_change)} points")
        critical_new = [i for i in new_items if i.severity in ("critical", "high")]
        if critical_new:
            alerts.append(f"{len(critical_new)} new critical/high findings detected")

        old_scan_ts = os.path.basename(old_dir)
        new_scan_ts = os.path.basename(new_dir)

        report = DiffReport(
            old_scan=old_scan_ts,
            new_scan=new_scan_ts,
            score_change=score_change,
            new_findings=new_items,
            resolved_findings=resolved_items,
            alerts=alerts,
        )

        logger.info("diff_complete",
                    score_change=score_change,
                    new=len(new_items),
                    resolved=len(resolved_items),
                    alerts=len(alerts))
        return report

    def _load_json(self, path: str) -> dict:
        if not os.path.isfile(path):
            return {}
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _extract_finding_keys(self, findings_data: dict) -> set[tuple[str, str]]:
        keys = set()
        for module in findings_data.get("modules", []):
            for finding in module.get("findings", []):
                keys.add((finding.get("severity", ""), finding.get("title", "")))
        return keys


def save_diff(diff_report: DiffReport, scan_dir: str) -> None:
    """Save diff report (atomic write)."""
    path = os.path.join(scan_dir, "diff.json")
    safe_write_json(path, diff_report.to_dict())
    logger.info("diff_saved", path=path)
