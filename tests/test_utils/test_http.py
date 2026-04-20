from unittest.mock import patch, MagicMock
import pytest
import requests
from cypulse.utils.http import http_get


def _mock_response(status=200):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status
    return resp


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
