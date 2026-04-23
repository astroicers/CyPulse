from __future__ import annotations
from collections import Counter
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
class Certificate:
    crt_id: str
    logged_at: str = ""
    not_before: str = ""
    not_after: str = ""
    common_name: str = ""
    sans: list[str] = field(default_factory=list)
    issuer: str = ""


@dataclass
class Assets:
    domain: str
    timestamp: str
    subdomains: list[Asset] = field(default_factory=list)
    certificates: list[Certificate] = field(default_factory=list)

    @property
    def total_subdomains(self) -> int:
        return len(self.subdomains)

    @property
    def total_live(self) -> int:
        return sum(1 for a in self.subdomains if a.ip)

    @property
    def total_http(self) -> int:
        return sum(1 for a in self.subdomains if a.http_status)

    @property
    def total_certificates(self) -> int:
        return len(self.certificates)

    @property
    def wildcard_certificates(self) -> int:
        return sum(
            1 for c in self.certificates
            if any(s.startswith("*.") for s in c.sans)
            or c.common_name.startswith("*.")
        )

    @property
    def latest_certificate(self) -> Certificate | None:
        if not self.certificates:
            return None
        return max(
            self.certificates,
            key=lambda c: (c.logged_at or "", c.not_before or ""),
        )

    @property
    def earliest_certificate(self) -> Certificate | None:
        if not self.certificates:
            return None
        dated = [c for c in self.certificates if c.logged_at or c.not_before]
        if not dated:
            return None
        return min(
            dated,
            key=lambda c: (c.logged_at or c.not_before, c.not_before or ""),
        )

    @property
    def issuer_stats(self) -> list[tuple[str, int]]:
        counter: Counter[str] = Counter()
        for c in self.certificates:
            issuer = c.issuer or "Unknown"
            counter[issuer] += 1
        return counter.most_common()

    def to_dict(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)
