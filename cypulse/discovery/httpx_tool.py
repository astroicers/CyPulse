from __future__ import annotations
import json
import structlog
from cypulse.discovery.base import DiscoveryTool
from cypulse.utils.subprocess import run_cmd, check_tool

logger = structlog.get_logger()


class HttpxTool(DiscoveryTool):

    def name(self) -> str:
        return "httpx"

    def run(self, domain: str, config: dict) -> list[dict]:
        """Run httpx on subdomains (newline-separated input)."""
        if not check_tool("httpx"):
            logger.warning("httpx_not_found", tool=self.name())
            return []

        cmd = [
            "httpx", "-silent", "-json",
            "-status-code", "-title", "-tech-detect",
            "-tls-grab", "-follow-redirects",
        ]

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
            logger.error("httpx_failed", error=str(e))
            return []

        results = []
        for line in proc.stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                results.append({
                    "subdomain": data.get("input", data.get("url", "")),
                    "url": data.get("url", ""),
                    "http_status": data.get("status_code"),
                    "http_title": data.get("title", ""),
                    "tls_version": data.get("tls", {}).get("version", None) if isinstance(data.get("tls"), dict) else None,
                    "tech": data.get("tech", []),
                    "content_length": data.get("content_length"),
                    "source": "httpx",
                })
            except json.JSONDecodeError:
                continue

        logger.info("httpx_complete", count=len(results))
        return results
