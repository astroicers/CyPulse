from __future__ import annotations
import json
import structlog
from cypulse.discovery.base import DiscoveryTool
from cypulse.utils.subprocess import check_tool

logger = structlog.get_logger()


class NaabuTool(DiscoveryTool):

    def name(self) -> str:
        return "naabu"

    def run(self, domain: str, config: dict) -> list[dict]:
        """Run naabu port scan (newline-separated hosts input)."""
        if not check_tool("naabu"):
            logger.warning("naabu_not_found", tool=self.name())
            return []

        cmd = [
            "naabu", "-silent", "-json",
            "-top-ports", "1000",
        ]

        rate = config.get("rate_limit")
        if rate:
            cmd.extend(["-rate", str(rate)])

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
            logger.error("naabu_failed", error=str(e))
            return []

        results = []
        for line in proc.stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                results.append({
                    "host": data.get("host", data.get("ip", "")),
                    "port": data.get("port"),
                    "source": "naabu",
                })
            except json.JSONDecodeError:
                continue

        logger.info("naabu_complete", count=len(results))
        return results
