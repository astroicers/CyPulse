from __future__ import annotations
import json
import os
import structlog
from cypulse.models import Score, ScoreExplanation, Findings
from cypulse.scoring.weights import WEIGHTS, get_grade

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

            if deduction > 0:
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
    os.makedirs(scan_dir, exist_ok=True)
    path = os.path.join(scan_dir, "score.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(score.to_dict(), f, ensure_ascii=False, indent=2)
    logger.info("score_saved", path=path)
