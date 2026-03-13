from __future__ import annotations
import json
import structlog
from cypulse.discovery.base import DiscoveryTool
from cypulse.utils.subprocess import run_cmd, check_tool

logger = structlog.get_logger()

_SECURITY_HEADER_NAMES = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def _extract_security_headers(raw_headers: dict) -> dict:
    """從 PD httpx 的 snake_case header dict 提取安全相關 headers。

    PD httpx 回傳 header key 格式為 snake_case（如 strict_transport_security）。
    轉換回標準 kebab-case（如 strict-transport-security）以供 M1 分析模組使用。
    """
    if not isinstance(raw_headers, dict):
        return {}
    result = {}
    for header_name in _SECURITY_HEADER_NAMES:
        snake_key = header_name.replace("-", "_")
        value = raw_headers.get(snake_key)
        if value:
            result[header_name] = value
    return result


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
            "-include-response-header",
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
                    "security_headers": _extract_security_headers(data.get("header", {})),
                    "source": "httpx",
                })
            except json.JSONDecodeError:
                continue

        logger.info("httpx_complete", count=len(results))
        return results
