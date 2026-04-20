from __future__ import annotations
import socket
import time
from urllib.parse import urlparse
import structlog
import requests

logger = structlog.get_logger()


class SourceUnavailable(requests.ConnectionError):
    """來源不可用（DNS 黑洞 / NXDOMAIN / circuit open）。

    繼承 requests.ConnectionError 讓既有 except 子句仍能捕捉；
    額外帶 reason 欄位供 caller 的 _classify_error 做更精準分類。
    """

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# DNS 黑洞常見的 sentinel IP（resolver 回傳這些代表被攔截）
_DNS_BLACKHOLE_IPS = frozenset({"0.0.0.0", "127.0.0.1", "::", "::1"})
_DNS_CACHE_TTL = 300.0
_DNS_LOOKUP_TIMEOUT = 5.0

# Circuit breaker：連續失敗達閾值即 short-circuit
_CIRCUIT_THRESHOLD = 3

_dns_cache: dict[str, tuple[float, str | None]] = {}
_circuit_state: dict[str, int] = {}


def reset_http_state() -> None:
    """清空 DNS cache 與 circuit breaker 狀態（test 用）。"""
    _dns_cache.clear()
    _circuit_state.clear()


def _check_dns(host: str) -> str | None:
    if not host:
        return None
    now = time.monotonic()
    cached = _dns_cache.get(host)
    if cached and (now - cached[0]) < _DNS_CACHE_TTL:
        return cached[1]

    prev_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(_DNS_LOOKUP_TIMEOUT)
    try:
        ip = socket.gethostbyname(host)
        reason = "dns_blackholed" if ip in _DNS_BLACKHOLE_IPS else None
    except socket.gaierror:
        reason = "dns_nxdomain"
    except OSError:
        # DNS lookup timeout 等，不 cache，讓下次再試
        return None
    finally:
        socket.setdefaulttimeout(prev_timeout)

    _dns_cache[host] = (now, reason)
    return reason


def _circuit_is_open(host: str) -> bool:
    return _circuit_state.get(host, 0) >= _CIRCUIT_THRESHOLD


def _circuit_record_failure(host: str) -> None:
    _circuit_state[host] = _circuit_state.get(host, 0) + 1


def _circuit_record_success(host: str) -> None:
    _circuit_state.pop(host, None)


def http_get(
    url: str,
    *,
    max_retries: int = 2,
    retry_delay: float = 1.0,
    max_backoff: float = 30.0,
    retry_on_status: tuple[int, ...] = (429, 500, 502, 503, 504),
    **kwargs,
) -> requests.Response:
    """帶 retry + DNS pre-flight + circuit breaker 的 requests.get。

    穩定性層：
      1. DNS pre-flight：host resolve 到 blackhole sentinel 或 NXDOMAIN 直接
         raise SourceUnavailable，不發 HTTP
      2. Circuit breaker：同一 host 連續 3 次 exception 失敗後 short-circuit
      3. Retry：網路 exception 或 retry_on_status 觸發指數退避重試
    """
    host = urlparse(url).hostname or ""

    dns_reason = _check_dns(host)
    if dns_reason:
        logger.info("http_preflight_skip", url=url, host=host, reason=dns_reason)
        raise SourceUnavailable(dns_reason)

    if _circuit_is_open(host):
        logger.info("http_circuit_skip", url=url, host=host)
        raise SourceUnavailable("circuit_open")

    for attempt in range(max_retries + 1):
        try:
            resp = requests.get(url, **kwargs)
            if resp.status_code in retry_on_status:
                if attempt < max_retries:
                    delay = min(retry_delay * (2 ** attempt), max_backoff)
                    logger.warning(
                        "http_retry",
                        url=url,
                        attempt=attempt + 1,
                        reason=f"http_{resp.status_code}",
                        delay=delay,
                    )
                    time.sleep(delay)
                    continue
                # status retry 耗盡 → 視為失敗計入 circuit breaker
                _circuit_record_failure(host)
                return resp
            _circuit_record_success(host)
            return resp
        except (requests.ConnectionError, requests.Timeout) as e:
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
                _circuit_record_failure(host)
                raise

    # unreachable; loop 總會 return 或 raise
    raise RuntimeError("http_get: unexpected loop exit")