from __future__ import annotations
import subprocess
import shutil
import structlog

logger = structlog.get_logger()


def check_tool(name: str) -> bool:
    return shutil.which(name) is not None


def run_cmd(
    cmd: list[str],
    timeout: int = 300,
    check: bool = True,
) -> subprocess.CompletedProcess:
    logger.debug("run_cmd", cmd=" ".join(cmd), timeout=timeout)
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
        logger.error("run_cmd_timeout", cmd=" ".join(cmd), timeout=timeout)
        raise
    except subprocess.CalledProcessError as e:
        logger.error("run_cmd_failed", cmd=" ".join(cmd), returncode=e.returncode, stderr=e.stderr[:500] if e.stderr else "")
        raise
