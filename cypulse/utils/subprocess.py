from __future__ import annotations
import subprocess
import shutil
import time
import structlog

logger = structlog.get_logger()


def check_tool(name: str) -> bool:
    return shutil.which(name) is not None


def run_cmd(
    cmd: list[str],
    timeout: int = 300,
    check: bool = True,
    max_retries: int = 0,
    retry_delay: float = 5.0,
    max_backoff: float = 60.0,
) -> subprocess.CompletedProcess:
    logger.debug("run_cmd", cmd=" ".join(cmd), timeout=timeout, max_retries=max_retries)
    for attempt in range(max_retries + 1):
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=check,
            )
            return result
        except subprocess.TimeoutExpired:
            if attempt < max_retries:
                delay = min(retry_delay * (2 ** attempt), max_backoff)
                logger.warning(
                    "run_cmd_retry", cmd=" ".join(cmd),
                    attempt=attempt + 1, reason="timeout", delay=delay
                )
                time.sleep(delay)
            else:
                logger.error("run_cmd_timeout", cmd=" ".join(cmd), timeout=timeout)
                raise
        except subprocess.CalledProcessError as e:
            if attempt < max_retries:
                delay = min(retry_delay * (2 ** attempt), max_backoff)
                logger.warning(
                    "run_cmd_retry", cmd=" ".join(cmd),
                    attempt=attempt + 1, reason="failed", delay=delay
                )
                time.sleep(delay)
            else:
                logger.error(
                    "run_cmd_failed", cmd=" ".join(cmd),
                    returncode=e.returncode,
                    stderr=e.stderr[:500] if e.stderr else "",
                )
                raise
