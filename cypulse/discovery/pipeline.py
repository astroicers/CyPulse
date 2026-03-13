from __future__ import annotations
import os
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import structlog
from cypulse.models import Asset, Assets
from cypulse.discovery.subfinder import SubfinderTool
from cypulse.discovery.amass import AmassTool
from cypulse.discovery.dnsx import DnsxTool, resolve_subdomains
from cypulse.discovery.httpx_tool import HttpxTool
from cypulse.discovery.naabu import NaabuTool

logger = structlog.get_logger()


def run_discovery(domain: str, config: dict) -> Assets:
    """Execute the full asset discovery pipeline."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%S")

    # Step 1: Subdomain enumeration (subfinder + amass)
    logger.info("discovery_step", step="subdomain_enumeration")
    subfinder = SubfinderTool()
    amass = AmassTool()

    with ThreadPoolExecutor(max_workers=2) as executor:
        sf_future = executor.submit(subfinder.run, domain, config)
        am_future = executor.submit(amass.run, domain, config)
        sf_results = sf_future.result()
        am_results = am_future.result()

    # Merge and deduplicate
    seen = set()
    all_subdomains: list[str] = []
    for item in sf_results + am_results:
        sub = item.get("subdomain", "").strip().lower()
        if sub and sub not in seen:
            seen.add(sub)
            all_subdomains.append(sub)

    # Always include the base domain
    if domain.lower() not in seen:
        all_subdomains.insert(0, domain.lower())

    logger.info("discovery_subdomains", total=len(all_subdomains))

    # Step 2: DNS resolution (dnsx)
    logger.info("discovery_step", step="dns_resolution")
    dns_results = resolve_subdomains(all_subdomains, config)

    # Build subdomain -> IP mapping
    dns_map: dict[str, str | None] = {}
    for r in dns_results:
        sub = r.get("subdomain", "").lower()
        dns_map[sub] = r.get("ip")

    # Step 3: Port scan (naabu)
    logger.info("discovery_step", step="port_scan")
    naabu = NaabuTool()
    live_hosts = [s for s in all_subdomains if dns_map.get(s)]
    port_input = "\n".join(live_hosts)
    port_results = naabu.run(port_input, config)

    # Build host -> ports mapping
    port_map: dict[str, list[int]] = {}
    for r in port_results:
        host = r.get("host", "").lower()
        port = r.get("port")
        if host and port:
            port_map.setdefault(host, []).append(port)

    # Step 4: HTTP probing (httpx)
    logger.info("discovery_step", step="http_probing")
    httpx = HttpxTool()
    http_input = "\n".join(live_hosts)
    http_results = httpx.run(http_input, config)

    # Build subdomain -> http info mapping
    http_map: dict[str, dict] = {}
    for r in http_results:
        sub = r.get("subdomain", "").lower()
        if sub:
            http_map[sub] = r

    # Step 5: Assemble Assets
    assets_list: list[Asset] = []
    for sub in all_subdomains:
        http_info = http_map.get(sub, {})
        asset = Asset(
            subdomain=sub,
            ip=dns_map.get(sub),
            ports=sorted(port_map.get(sub, [])),
            http_status=http_info.get("http_status"),
            http_title=http_info.get("http_title"),
            tls_version=http_info.get("tls_version"),
            security_headers=http_info.get("security_headers", {}),
        )
        assets_list.append(asset)

    assets = Assets(
        domain=domain,
        timestamp=timestamp,
        subdomains=assets_list,
    )

    logger.info(
        "discovery_complete",
        domain=domain,
        total=assets.total_subdomains,
        live=assets.total_live,
        http=assets.total_http,
    )

    return assets


def save_assets(assets: Assets, output_dir: str) -> str:
    """Save assets to JSON file, return path."""
    scan_dir = os.path.join(output_dir, assets.domain, assets.timestamp)
    os.makedirs(scan_dir, exist_ok=True)
    path = os.path.join(scan_dir, "assets.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(assets.to_dict(), f, ensure_ascii=False, indent=2)
    logger.info("assets_saved", path=path)
    return scan_dir
