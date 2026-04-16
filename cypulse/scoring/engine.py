from __future__ import annotations
import os
import structlog
from cypulse.models import Score, ScoreExplanation, Findings, ModuleResult
from cypulse.scoring.weights import WEIGHTS, get_grade
from cypulse.utils.io import safe_write_json

logger = structlog.get_logger()


def _compute_module_coverage(module_result: ModuleResult) -> float:
    """計算單一模組的來源覆蓋率。

    - 無 sources 定義的模組（M3/M4/M5/M7）：依 status 推斷
        * success → 1.0
        * partial → 0.5（部分資料，無法精確量化）
        * error   → 0.0（模組整個失敗，不能謊報 1.0）
        * skipped → 1.0（模組未啟用，不計入分母）
    - 有 sources：sum(success weight) / sum(non-skipped weight)
    - 全部 skipped → 1.0（視為此次掃描無此模組能力需求）
    """
    if not module_result.sources:
        status = module_result.status
        if status == "error":
            return 0.0
        if status == "partial":
            return 0.5
        return 1.0  # success / skipped
    non_skipped = [s for s in module_result.sources if s.status != "skipped"]
    if not non_skipped:
        return 1.0
    total_weight = sum(s.weight for s in non_skipped)
    if total_weight == 0:
        return 1.0
    success_weight = sum(s.weight for s in non_skipped if s.status == "success")
    return success_weight / total_weight


def _compute_confidence(source_coverage: dict[str, float]) -> float:
    """整體信心 = 各模組覆蓋率 × 模組權重的加權平均。

    若某模組缺在 WEIGHTS（理論上不會）→ 該模組用預設權重 0 跳過。
    """
    total_weight = 0.0
    weighted_sum = 0.0
    for mid, coverage in source_coverage.items():
        module_weight = WEIGHTS.get(mid, {}).get("weight", 0.0)
        total_weight += module_weight
        weighted_sum += coverage * module_weight
    if total_weight == 0:
        return 1.0
    return weighted_sum / total_weight


class ScoringEngine:

    def calculate(self, findings: Findings) -> Score:
        dimensions: dict[str, int] = {}
        explanations: list[ScoreExplanation] = []
        source_coverage: dict[str, float] = {}
        total_duration = 0.0

        for module_result in findings.modules:
            mid = module_result.module_id
            dimensions[mid] = module_result.score
            total_duration += module_result.execution_time
            source_coverage[mid] = _compute_module_coverage(module_result)

            # Generate explanations for deductions
            weight_info = WEIGHTS.get(mid, {})
            max_score = weight_info.get("max_score", 0)
            deduction = max_score - module_result.score
            module_name = weight_info.get("name", mid)

            if module_result.status == "skipped":
                explanations.append(ScoreExplanation(
                    module_id=mid,
                    reason=f"{module_name} 未執行（缺少 API 金鑰）",
                    deduction=0,
                ))
            elif deduction > 0:
                if module_result.status in ("error", "partial"):
                    explanations.append(ScoreExplanation(
                        module_id=mid,
                        reason=f"{module_name} 未完成檢測 (status: {module_result.status})",
                        deduction=deduction,
                    ))
                else:
                    for finding in module_result.findings:
                        if finding.score_impact > 0:
                            explanations.append(ScoreExplanation(
                                module_id=mid,
                                reason=finding.title,
                                deduction=finding.score_impact,
                            ))

            # 來源覆蓋率 < 1.0 時附上說明（不扣分，僅資訊）
            coverage = source_coverage[mid]
            if coverage < 1.0:
                failed_srcs = [
                    s.source_id for s in module_result.sources
                    if s.status == "failed"
                ]
                explanations.append(ScoreExplanation(
                    module_id=mid,
                    reason=(
                        f"{module_name} 部分來源未回應"
                        f"（信心 {coverage * 100:.0f}%"
                        f"，失效來源: {', '.join(failed_srcs) if failed_srcs else 'N/A'}）"
                    ),
                    deduction=0,
                ))

        total = sum(dimensions.values())
        grade = get_grade(total)
        confidence = _compute_confidence(source_coverage)

        score = Score(
            total=total,
            grade=grade,
            dimensions=dimensions,
            explanations=explanations,
            scan_duration=total_duration,
            confidence=confidence,
            source_coverage=source_coverage,
        )

        logger.info(
            "scoring_complete",
            total=total, grade=grade,
            dimensions=dimensions,
            confidence=f"{confidence:.2%}",
        )
        return score

    def explain(self, score: Score) -> list[ScoreExplanation]:
        return score.explanations


def save_score(score: Score, scan_dir: str) -> None:
    path = os.path.join(scan_dir, "score.json")
    safe_write_json(path, score.to_dict())
    logger.info("score_saved", path=path)
