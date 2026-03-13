from __future__ import annotations
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import structlog
import requests

logger = structlog.get_logger()

_VALID_SUBDOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$")


def _is_valid_subdomain(sub: str, domain: str) -> bool:
    """驗證子網域格式合法且屬於目標域名。"""
    if not sub or len(sub) > 253:
        return False
    if not sub.endswith(f".{domain}") and sub != domain:
        return False
    if "*" in sub:
        return False
    return bool(_VALID_SUBDOMAIN_RE.match(sub))


def query_crtsh(domain: str, timeout: int = 30) -> list[str]:
    """crt.sh Certificate Transparency：查域名的 CT 記錄。"""
    try:
        resp = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            headers={"user-agent": "CyPulse"},
            timeout=timeout,
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        subs: set[str] = set()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower()
                if _is_valid_subdomain(name, domain):
                    subs.add(name)
        logger.info("crtsh_complete", domain=domain, count=len(subs))
        return list(subs)
    except Exception as e:
        logger.error("crtsh_failed", domain=domain, error=str(e))
    return []


def query_hackertarget(domain: str, timeout: int = 15) -> list[str]:
    """HackerTarget：免費 DNS 查詢（CSV 格式）。"""
    try:
        resp = requests.get(
            "https://api.hackertarget.com/hostsearch/",
            params={"q": domain},
            headers={"user-agent": "CyPulse"},
            timeout=timeout,
        )
        if resp.status_code != 200:
            return []
        text = resp.text.strip()
        if text.startswith("error") or not text:
            return []
        subs: set[str] = set()
        for line in text.split("\n"):
            parts = line.strip().split(",")
            if parts:
                name = parts[0].strip().lower()
                if _is_valid_subdomain(name, domain):
                    subs.add(name)
        logger.info("hackertarget_complete", domain=domain, count=len(subs))
        return list(subs)
    except Exception as e:
        logger.error("hackertarget_failed", domain=domain, error=str(e))
    return []


def query_subdomain_center(domain: str, timeout: int = 15) -> list[str]:
    """subdomain.center：免費子網域查詢（JSON array）。"""
    try:
        resp = requests.get(
            "https://api.subdomain.center/",
            params={"domain": domain},
            headers={"user-agent": "CyPulse"},
            timeout=timeout,
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        if not isinstance(data, list):
            return []
        subs: set[str] = set()
        for name in data:
            if isinstance(name, str):
                name = name.strip().lower()
                if _is_valid_subdomain(name, domain):
                    subs.add(name)
        logger.info("subdomain_center_complete", domain=domain, count=len(subs))
        return list(subs)
    except Exception as e:
        logger.error("subdomain_center_failed", domain=domain, error=str(e))
    return []


def query_web_sources(domain: str, config: dict) -> list[dict]:
    """並行查詢所有免費 Web 來源，回傳統一格式 [{"subdomain": "..."}]。"""
    sources = [
        ("crtsh", query_crtsh),
        ("hackertarget", query_hackertarget),
        ("subdomain_center", query_subdomain_center),
    ]

    all_subs: set[str] = set()
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(fn, domain): name
            for name, fn in sources
        }
        for future in as_completed(futures):
            source_name = futures[future]
            try:
                results = future.result()
                all_subs.update(results)
            except Exception as e:
                logger.error("web_source_failed", source=source_name, error=str(e))

    logger.info("web_sources_complete", domain=domain, total=len(all_subs))
    return [{"subdomain": sub} for sub in sorted(all_subs)]
