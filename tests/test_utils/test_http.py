import socket
from unittest.mock import patch, MagicMock
import pytest
import requests
from cypulse.utils.http import http_get, SourceUnavailable, reset_http_state


def _mock_response(status=200):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status
    return resp


@pytest.fixture(autouse=True)
def _clear_state_and_mock_dns():
    """預設：清 module-level state + DNS 回正常 IP。
    要測 DNS 行為的 test 內自行覆寫 gethostbyname patch。"""
    reset_http_state()
    with patch("cypulse.utils.http.socket.gethostbyname", return_value="1.2.3.4"):
        yield
    reset_http_state()


class TestHttpGet:
    @patch("cypulse.utils.http.time.sleep")
    @patch("cypulse.utils.http.requests.get")
    def test_success_first_try_no_retry(self, mock_get, mock_sleep):
        mock_get.return_value = _mock_response(200)
        resp = http_get("https://example.com")
        assert resp.status_code == 200
        assert mock_get.call_count == 1
        assert mock_sleep.call_count == 0

    @patch("cypulse.utils.http.time.sleep")
    @patch("cypulse.utils.http.requests.get")
    def test_retry_on_connection_error_then_success(self, mock_get, mock_sleep):
        mock_get.side_effect = [
            requests.ConnectionError("refused"),
            _mock_response(200),
        ]
        resp = http_get("https://example.com")
        assert resp.status_code == 200
        assert mock_get.call_count == 2
        assert mock_sleep.call_count == 1

    @patch("cypulse.utils.http.time.sleep")
    @patch("cypulse.utils.http.requests.get")
    def test_retry_on_read_timeout_then_success(self, mock_get, mock_sleep):
        mock_get.side_effect = [
            requests.Timeout("read timed out"),
            _mock_response(200),
        ]
        resp = http_get("https://example.com")
        assert resp.status_code == 200
        assert mock_get.call_count == 2

    @patch("cypulse.utils.http.time.sleep")
    @patch("cypulse.utils.http.requests.get")
    def test_retry_exhausted_raises(self, mock_get, mock_sleep):
        mock_get.side_effect = requests.ConnectionError("persistent refused")
        with pytest.raises(requests.ConnectionError, match="persistent refused"):
            http_get("https://example.com", max_retries=2)
        assert mock_get.call_count == 3  # initial + 2 retries

    @patch("cypulse.utils.http.time.sleep")
    @patch("cypulse.utils.http.requests.get")
    def test_retry_on_5xx_status(self, mock_get, mock_sleep):
        mock_get.side_effect = [_mock_response(503), _mock_response(200)]
        resp = http_get("https://example.com")
        assert resp.status_code == 200
        assert mock_get.call_count == 2

    @patch("cypulse.utils.http.time.sleep")
    @patch("cypulse.utils.http.requests.get")
    def test_no_retry_on_404(self, mock_get, mock_sleep):
        mock_get.return_value = _mock_response(404)
        resp = http_get("https://example.com")
        assert resp.status_code == 404
        assert mock_get.call_count == 1
        assert mock_sleep.call_count == 0

    @patch("cypulse.utils.http.time.sleep")
    @patch("cypulse.utils.http.requests.get")
    def test_exponential_backoff_delays(self, mock_get, mock_sleep):
        mock_get.side_effect = [
            requests.ConnectionError("1"),
            requests.ConnectionError("2"),
            _mock_response(200),
        ]
        http_get("https://example.com", max_retries=2, retry_delay=1.0)
        assert mock_sleep.call_count == 2
        delays = [c.args[0] for c in mock_sleep.call_args_list]
        assert delays == [1.0, 2.0]

    @patch("cypulse.utils.http.time.sleep")
    @patch("cypulse.utils.http.requests.get")
    def test_max_backoff_cap(self, mock_get, mock_sleep):
        mock_get.side_effect = [
            requests.ConnectionError("1"),
            requests.ConnectionError("2"),
            _mock_response(200),
        ]
        http_get(
            "https://example.com",
            max_retries=2,
            retry_delay=1.0,
            max_backoff=1.5,
        )
        delays = [c.args[0] for c in mock_sleep.call_args_list]
        assert delays == [1.0, 1.5]  # 第二次本應 2.0，被 cap 到 1.5

    @patch("cypulse.utils.http.time.sleep")
    @patch("cypulse.utils.http.requests.get")
    def test_kwargs_passthrough(self, mock_get, mock_sleep):
        mock_get.return_value = _mock_response(200)
        http_get(
            "https://example.com",
            params={"q": "x"},
            headers={"user-agent": "CyPulse"},
            timeout=5,
        )
        assert mock_get.call_count == 1
        _, kwargs = mock_get.call_args
        assert kwargs["params"] == {"q": "x"}
        assert kwargs["headers"] == {"user-agent": "CyPulse"}
        assert kwargs["timeout"] == 5


class TestDnsPreflight:
    @patch("cypulse.utils.http.time.sleep")
    @patch("cypulse.utils.http.requests.get")
    def test_dns_blackhole_raises_source_unavailable(self, mock_get, mock_sleep):
        """DNS 被黑洞（resolve 到 0.0.0.0）應立即 raise，不發 HTTP"""
        with patch("cypulse.utils.http.socket.gethostbyname", return_value="0.0.0.0"):
            with pytest.raises(SourceUnavailable) as exc_info:
                http_get("http://ip-api.com/json/8.8.8.8")
        assert exc_info.value.reason == "dns_blackholed"
        assert mock_get.call_count == 0  # 沒發任何 HTTP

    @patch("cypulse.utils.http.time.sleep")
    @patch("cypulse.utils.http.requests.get")
    def test_dns_nxdomain_raises_source_unavailable(self, mock_get, mock_sleep):
        with patch(
            "cypulse.utils.http.socket.gethostbyname",
            side_effect=socket.gaierror("not found"),
        ):
            with pytest.raises(SourceUnavailable) as exc_info:
                http_get("https://dead.example.invalid/")
        assert exc_info.value.reason == "dns_nxdomain"
        assert mock_get.call_count == 0

    @patch("cypulse.utils.http.time.sleep")
    @patch("cypulse.utils.http.requests.get")
    def test_source_unavailable_is_connection_error_subclass(
        self, mock_get, mock_sleep
    ):
        """既有 except requests.ConnectionError 應該仍能捕捉"""
        assert issubclass(SourceUnavailable, requests.ConnectionError)

    @patch("cypulse.utils.http.time.sleep")
    @patch("cypulse.utils.http.requests.get")
    def test_dns_cache_avoids_repeated_lookup(self, mock_get, mock_sleep):
        """連續呼叫同一 host，DNS 只 resolve 一次（cache 生效）"""
        with patch(
            "cypulse.utils.http.socket.gethostbyname",
            return_value="0.0.0.0",
        ) as mock_dns:
            for _ in range(3):
                with pytest.raises(SourceUnavailable):
                    http_get("http://ip-api.com/json/1.1.1.1")
                with pytest.raises(SourceUnavailable):
                    http_get("http://ip-api.com/json/2.2.2.2")
            assert mock_dns.call_count == 1  # cache 命中

    @patch("cypulse.utils.http.time.sleep")
    @patch("cypulse.utils.http.requests.get")
    def test_dns_normal_resolve_proceeds_to_http(self, mock_get, mock_sleep):
        mock_get.return_value = _mock_response(200)
        with patch("cypulse.utils.http.socket.gethostbyname", return_value="93.184.216.34"):
            resp = http_get("https://example.com/x")
        assert resp.status_code == 200
        assert mock_get.call_count == 1


class TestCircuitBreaker:
    @patch("cypulse.utils.http.time.sleep")
    @patch("cypulse.utils.http.requests.get")
    def test_circuit_opens_after_threshold_consecutive_failures(
        self, mock_get, mock_sleep
    ):
        """連續 3 次 ConnectionError 後，第 4 次應直接 short-circuit"""
        mock_get.side_effect = requests.ConnectionError("refused")
        for _ in range(3):
            with pytest.raises(requests.ConnectionError):
                http_get("https://flaky.example.com/", max_retries=0)
        # 前 3 次皆真的發 HTTP
        assert mock_get.call_count == 3
        # 第 4 次 circuit open
        with pytest.raises(SourceUnavailable) as exc_info:
            http_get("https://flaky.example.com/", max_retries=0)
        assert exc_info.value.reason == "circuit_open"
        assert mock_get.call_count == 3  # 沒新增 HTTP 呼叫

    @patch("cypulse.utils.http.time.sleep")
    @patch("cypulse.utils.http.requests.get")
    def test_circuit_resets_on_success(self, mock_get, mock_sleep):
        """任何一次成功呼叫應重置計數器"""
        mock_get.side_effect = [
            requests.ConnectionError("x"),
            requests.ConnectionError("x"),
            _mock_response(200),
            requests.ConnectionError("x"),
            requests.ConnectionError("x"),
        ]
        # 2 次失敗
        for _ in range(2):
            with pytest.raises(requests.ConnectionError):
                http_get("https://x.example.com/", max_retries=0)
        # 1 次成功 → 重置
        assert http_get("https://x.example.com/", max_retries=0).status_code == 200
        # 再 2 次失敗（counter 重置後不應觸發 circuit，僅 2 次 < 閾值 3）
        for _ in range(2):
            with pytest.raises(requests.ConnectionError):
                http_get("https://x.example.com/", max_retries=0)
        assert mock_get.call_count == 5

    @patch("cypulse.utils.http.time.sleep")
    @patch("cypulse.utils.http.requests.get")
    def test_circuit_opens_on_exhausted_5xx(self, mock_get, mock_sleep):
        """持續 429/5xx 所有 retry 耗盡也應計入 circuit breaker"""
        mock_get.return_value = _mock_response(429)
        for _ in range(3):
            resp = http_get("https://ratelimited.example.com/", max_retries=0)
            assert resp.status_code == 429
        # 第 4 次應 short-circuit，不發 HTTP
        prev_calls = mock_get.call_count
        with pytest.raises(SourceUnavailable):
            http_get("https://ratelimited.example.com/", max_retries=0)
        assert mock_get.call_count == prev_calls

    @patch("cypulse.utils.http.time.sleep")
    @patch("cypulse.utils.http.requests.get")
    def test_circuit_is_per_host(self, mock_get, mock_sleep):
        """host A 的 circuit open 不影響 host B"""
        def side_effect(url, **kw):
            if "flaky" in url:
                raise requests.ConnectionError("refused")
            return _mock_response(200)
        mock_get.side_effect = side_effect
        for _ in range(3):
            with pytest.raises(requests.ConnectionError):
                http_get("https://flaky.example.com/", max_retries=0)
        # host A circuit open
        with pytest.raises(SourceUnavailable):
            http_get("https://flaky.example.com/", max_retries=0)
        # host B 依舊正常
        assert http_get("https://healthy.example.com/").status_code == 200
