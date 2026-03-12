from __future__ import annotations
import re

DOMAIN_PATTERN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)


def sanitize_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        from urllib.parse import urlparse
        domain = urlparse(domain).hostname or domain
    domain = domain.rstrip(".")
    if not DOMAIN_PATTERN.match(domain):
        raise ValueError(f"Invalid domain format: {domain}")
    return domain
