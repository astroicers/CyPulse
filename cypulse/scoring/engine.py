from __future__ import annotations
import os
import structlog
from cypulse.models import Score, ScoreExplanation, Findings
from cypulse.scoring.weights import WEIGHTS, get_grade
from cypulse.utils.io import safe_write_json

logger = structlog.get_logger()


class ScoringEngine:

    def calculate(self, findings: Findings) -> Score:
        dimensions: dict[str, int] = {}
        explanations: list[ScoreExplanation] = []
        total_duration = 0.0

        for module_result in findings.modules:
            mid = module_result.module_id
            dimensions[mid] = module_result.score
            total_duration += module_result.execution_time

            # Generate explanations for deductions
            weight_info = WEIGHTS.get(mid, {})
            max_score = weight_info.get("max_score", 0)
            deduction = max_score - module_result.score

            if module_result.status == "skipped":
                module_name = weight_info.get("name", mid)
                explanations.append(ScoreExplanation(
                    module_id=mid,
                    reason=f"{module_name} 未執行（缺少 API 金鑰）",
                    deduction=0,
                ))
            elif deduction > 0:
                if module_result.status in ("error", "partial"):
                    module_name = weight_info.get("name", mid)
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

        total = sum(dimensions.values())
        grade = get_grade(total)

        score = Score(
            total=total,
            grade=grade,
            dimensions=dimensions,
            explanations=explanations,
            scan_duration=total_duration,
        )

        logger.info("scoring_complete", total=total, grade=grade, dimensions=dimensions)
        return score

    def explain(self, score: Score) -> list[ScoreExplanation]:
        return score.explanations


def save_score(score: Score, scan_dir: str) -> None:
    path = os.path.join(scan_dir, "score.json")
    safe_write_json(path, score.to_dict())
    logger.info("score_saved", path=path)
