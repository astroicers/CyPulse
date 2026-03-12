from __future__ import annotations
import json
import structlog
from cypulse.discovery.base import DiscoveryTool
from cypulse.utils.subprocess import run_cmd, check_tool

logger = structlog.get_logger()


class SubfinderTool(DiscoveryTool):

    def name(self) -> str:
        return "subfinder"

    def run(self, domain: str, config: dict) -> list[dict]:
        if not check_tool("subfinder"):
            logger.warning("subfinder_not_found", tool=self.name())
            return []

        cmd = ["subfinder", "-d", domain, "-silent", "-json"]

        sources = config.get("api_keys", {})
        if sources:
            # subfinder uses provider config file, not CLI flags for API keys
            pass

        try:
            result = run_cmd(cmd, timeout=config.get("timeout", 300))
        except Exception as e:
            logger.error("subfinder_failed", error=str(e))
            return []

        subdomains = []
        for line in result.stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                subdomains.append({
                    "subdomain": data.get("host", ""),
                    "source": data.get("source", "subfinder"),
                })
            except json.JSONDecodeError:
                # Plain text output (one subdomain per line)
                subdomains.append({
                    "subdomain": line.strip(),
                    "source": "subfinder",
                })

        logger.info("subfinder_complete", domain=domain, count=len(subdomains))
        return subdomains
