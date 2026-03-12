from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class Finding:
    severity: str  # critical / high / medium / low / info
    title: str
    description: str
    evidence: str | None = None
    score_impact: int = 0


@dataclass
class ModuleResult:
    module_id: str  # M1 ~ M7
    module_name: str
    score: int
    max_score: int
    findings: list[Finding] = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)
    execution_time: float = 0.0
    status: str = "success"  # success / partial / error

    def to_dict(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)


@dataclass
class Findings:
    domain: str
    timestamp: str
    modules: list[ModuleResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)
