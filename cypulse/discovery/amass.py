from __future__ import annotations
import json
import structlog
from cypulse.discovery.base import DiscoveryTool
from cypulse.utils.subprocess import run_cmd, check_tool

logger = structlog.get_logger()


class AmassTool(DiscoveryTool):

    def name(self) -> str:
        return "amass"

    def run(self, domain: str, config: dict) -> list[dict]:
        if not check_tool("amass"):
            logger.warning("amass_not_found", tool=self.name())
            return []

        cmd = ["amass", "enum", "-passive", "-d", domain, "-json", "-"]

        try:
            result = run_cmd(cmd, timeout=config.get("timeout", 300), check=False)
        except Exception as e:
            logger.error("amass_failed", error=str(e))
            return []

        subdomains = []
        for line in result.stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                name = data.get("name", "")
                if name:
                    subdomains.append({
                        "subdomain": name,
                        "source": "amass",
                    })
            except json.JSONDecodeError:
                subdomains.append({
                    "subdomain": line.strip(),
                    "source": "amass",
                })

        logger.info("amass_complete", domain=domain, count=len(subdomains))
        return subdomains
