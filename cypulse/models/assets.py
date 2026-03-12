from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class Asset:
    subdomain: str
    ip: str | None = None
    ports: list[int] = field(default_factory=list)
    http_status: int | None = None
    http_title: str | None = None
    tls_version: str | None = None
    security_headers: dict = field(default_factory=dict)


@dataclass
class Assets:
    domain: str
    timestamp: str
    subdomains: list[Asset] = field(default_factory=list)

    @property
    def total_subdomains(self) -> int:
        return len(self.subdomains)

    @property
    def total_live(self) -> int:
        return sum(1 for a in self.subdomains if a.ip)

    @property
    def total_http(self) -> int:
        return sum(1 for a in self.subdomains if a.http_status)

    def to_dict(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)
