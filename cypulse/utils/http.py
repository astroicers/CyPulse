from __future__ import annotations
import time
import structlog
import requests

logger = structlog.get_logger()


def http_get(
    url: str,
    *,
    max_retries: int = 2,
    retry_delay: float = 1.0,
    max_backoff: float = 30.0,
    retry_on_status: tuple[int, ...] = (429, 500, 502, 503, 504),
    **kwargs,
) -> requests.Response:
    """帶 retry 的 requests.get。

    - 網路層 exception（ConnectionError/Timeout）觸發 retry
    - `retry_on_status` 指定的 HTTP 狀態碼觸發 retry
    - 指數退避：delay = min(retry_delay * 2^attempt, max_backoff)

    全部 retry 耗盡後：
      exception 路徑 → raise 原 exception（caller 既有 try/except 保留）
      status 路徑   → 回傳最後一次 response（caller 既有 status_code 檢查保留）

    kwargs 透傳給 requests.get（params / headers / timeout / ...）。
    """
    last_exc: Exception | None = None
    last_resp: requests.Response | None = None

    for attempt in range(max_retries + 1):
        try:
            resp = requests.get(url, **kwargs)
            if resp.status_code in retry_on_status and attempt < max_retries:
                delay = min(retry_delay * (2 ** attempt), max_backoff)
                logger.warning(
                    "http_retry",
                    url=url,
                    attempt=attempt + 1,
                    reason=f"http_{resp.status_code}",
                    delay=delay,
                )
                last_resp = resp
                time.sleep(delay)
                continue
            return resp
        except (requests.ConnectionError, requests.Timeout) as e:
            last_exc = e
            if attempt < max_retries:
                delay = min(retry_delay * (2 ** attempt), max_backoff)
                logger.warning(
                    "http_retry",
                    url=url,
                    attempt=attempt + 1,
                    reason=type(e).__name__,
                    delay=delay,
                )
                time.sleep(delay)
            else:
                raise

    # retry_on_status 耗盡時返回最後一次 response
    assert last_resp is not None  # exception path 已 raise
    return last_resp
