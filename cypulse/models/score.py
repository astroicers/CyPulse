from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class ScoreExplanation:
    module_id: str
    reason: str
    deduction: int


@dataclass
class Score:
    total: int
    grade: str  # A / B / C / D
    dimensions: dict[str, int] = field(default_factory=dict)
    explanations: list[ScoreExplanation] = field(default_factory=list)
    scan_duration: float = 0.0
    # 信心分數：0.0~1.0，反映資料來源覆蓋率（見 ADR-006）
    # 1.0 = 所有來源都成功；< 0.8 建議重跑
    confidence: float = 1.0
    # 各模組來源覆蓋率 {"M1": 0.6, "M2": 1.0, ...}
    source_coverage: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)


@dataclass
class DiffItem:
    category: str  # new_finding / resolved / score_change
    severity: str | None = None
    description: str = ""


@dataclass
class DiffReport:
    old_scan: str
    new_scan: str
    score_change: int = 0
    new_findings: list[DiffItem] = field(default_factory=list)
    resolved_findings: list[DiffItem] = field(default_factory=list)
    alerts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)
