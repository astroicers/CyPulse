from __future__ import annotations
import json
import structlog
from cypulse.discovery.base import DiscoveryTool
from cypulse.utils.subprocess import check_tool

logger = structlog.get_logger()


class DnsxTool(DiscoveryTool):

    def name(self) -> str:
        return "dnsx"

    def run(self, domain: str, config: dict) -> list[dict]:
        """Run dnsx on subdomains (domain as newline-separated string or single domain)."""
        if not check_tool("dnsx"):
            logger.warning("dnsx_not_found", tool=self.name())
            return []

        cmd = ["dnsx", "-silent", "-json", "-a", "-resp"]

        try:
            import subprocess as sp
            proc = sp.run(
                cmd,
                input=domain,
                capture_output=True,
                text=True,
                timeout=config.get("timeout", 300),
            )
        except Exception as e:
            logger.error("dnsx_failed", error=str(e))
            return []

        results = []
        for line in proc.stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                host = data.get("host", "")
                ips = data.get("a", [])
                if host:
                    results.append({
                        "subdomain": host,
                        "ip": ips[0] if ips else None,
                        "all_ips": ips,
                        "source": "dnsx",
                    })
            except json.JSONDecodeError:
                continue

        resolved = sum(1 for r in results if r.get("ip"))
        logger.info("dnsx_complete", total=len(results), resolved=resolved)
        return results


def resolve_subdomains(subdomains: list[str], config: dict) -> list[dict]:
    """Convenience function: resolve a list of subdomains via dnsx."""
    tool = DnsxTool()
    input_str = "\n".join(subdomains)
    return tool.run(input_str, config)
