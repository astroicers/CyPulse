from __future__ import annotations
import html as html_mod
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import structlog
from cypulse.utils.http import http_get

logger = structlog.get_logger()

_VALID_SUBDOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$")

# crt.sh HTML table row parser — JSON 後端掛掉時的 fallback。
# 欄位順序：crt.sh ID, Logged At, Not Before, Not After, Common Name, Matching Identities, Issuer
_CRTSH_ROW_RE = re.compile(
    r"<TR>\s*"
    r"<TD[^>]*><A[^>]*>(\d+)</A></TD>\s*"
    r"<TD[^>]*>([\d-]+)</TD>\s*"
    r"<TD[^>]*>([\d-]+)</TD>\s*"
    r"<TD[^>]*>([\d-]+)</TD>\s*"
    r"<TD[^>]*>(.*?)</TD>\s*"
    r"<TD[^>]*>(.*?)</TD>\s*"
    r"<TD[^>]*>(.*?)</TD>\s*"
    r"</TR>",
    re.I | re.S,
)


def _strip_tags(s: str) -> str:
    s = re.sub(r"<BR\s*/?>", "\n", s, flags=re.I)
    s = re.sub(r"<[^>]+>", "", s)
    return html_mod.unescape(s).strip()


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
    certs = query_crtsh_certificates(domain, timeout=timeout)
    subs: set[str] = set()
    for c in certs:
        for name in c.get("sans", []):
            if _is_valid_subdomain(name, domain):
                subs.add(name)
    return list(subs)


def query_crtsh_certificates(domain: str, timeout: int = 30) -> list[dict]:
    """crt.sh CT：回傳憑證 metadata 清單（給資訊展示用）。

    每筆 dict 欄位：
        crt_id, logged_at, not_before, not_after,
        common_name, sans (list[str]), issuer

    crt.sh 後端有兩條路，會獨立壞掉：
      1. JSON (`output=json`)：正常時好用、解析快
      2. HTML table：JSON 壞掉時仍可能可用，解析較吃力

    先試 JSON，非 200 時 fallback 到 HTML scrape。
    """
    certs = _crtsh_try_json(domain, timeout)
    if certs:
        logger.info("crtsh_complete", domain=domain, count=len(certs), source="json")
        return certs
    certs = _crtsh_try_html(domain, timeout)
    if certs:
        logger.info("crtsh_complete", domain=domain, count=len(certs), source="html")
        return certs
    logger.warning("crtsh_no_data", domain=domain)
    return []


def _crtsh_try_json(domain: str, timeout: int) -> list[dict]:
    try:
        resp = http_get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            headers={"user-agent": "CyPulse"},
            timeout=timeout,
        )
        if resp.status_code != 200:
            logger.warning("crtsh_json_http_error", domain=domain, status=resp.status_code)
            return []
        data = resp.json()
    except Exception as e:
        logger.warning("crtsh_json_failed", domain=domain, error=str(e))
        return []

    certs: list[dict] = []
    seen_ids: set[str] = set()
    for entry in data:
        cid = str(entry.get("id") or entry.get("min_cert_id") or "")
        if cid:
            if cid in seen_ids:
                continue
            seen_ids.add(cid)
        sans = []
        for name in (entry.get("name_value") or "").split("\n"):
            name = name.strip().lower()
            if name:
                sans.append(name)
        certs.append({
            "crt_id": cid,
            "logged_at": (entry.get("entry_timestamp") or "")[:10],
            "not_before": (entry.get("not_before") or "")[:10],
            "not_after": (entry.get("not_after") or "")[:10],
            "common_name": (entry.get("common_name") or "").strip().lower(),
            "sans": sans,
            "issuer": (entry.get("issuer_name") or "").strip(),
        })
    return certs


def _crtsh_try_html(domain: str, timeout: int) -> list[dict]:
    """Fallback：抓兩個 HTML endpoint 並合併去重。

    兩個 query 拿到的是互補集合：
      - Identity=%.<domain>：只含 SAN 匹配子網域的憑證
      - q=<domain>&group=none：含所有 exact + 相關憑證（未 group by）
    """
    by_id: dict[str, dict] = {}
    stray: list[dict] = []  # 沒有 crt_id 的筆，不參與去重
    for params in (
        {"Identity": f"%.{domain}"},
        {"q": domain, "group": "none"},
    ):
        try:
            resp = http_get(
                "https://crt.sh/",
                params=params,
                headers={"user-agent": "CyPulse"},
                timeout=timeout,
            )
            if resp.status_code != 200 or "<TABLE" not in resp.text.upper():
                logger.warning(
                    "crtsh_html_http_error",
                    domain=domain,
                    params=params,
                    status=resp.status_code,
                )
                continue
        except Exception as e:
            logger.warning("crtsh_html_failed", domain=domain, params=params, error=str(e))
            continue

        for m in _CRTSH_ROW_RE.finditer(resp.text):
            cid, logged, nb, na, cn, sans_raw, issuer = m.groups()
            rec = {
                "crt_id": cid,
                "logged_at": logged,
                "not_before": nb,
                "not_after": na,
                "common_name": _strip_tags(cn).lower(),
                "sans": [s for s in _strip_tags(sans_raw).split("\n") if s],
                "issuer": _strip_tags(issuer),
            }
            if cid:
                by_id[cid] = rec
            else:
                stray.append(rec)
    return list(by_id.values()) + stray


def query_hackertarget(domain: str, timeout: int = 15) -> list[str]:
    """HackerTarget：免費 DNS 查詢（CSV 格式）。"""
    try:
        resp = http_get(
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
        resp = http_get(
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
