import pytest
from unittest.mock import patch
from cypulse.utils.http import reset_http_state


@pytest.fixture(autouse=True)
def _isolate_http_state():
    """discovery 模組測試預設同 analysis：清 http state + bypass DNS 黑洞。"""
    reset_http_state()
    with patch("cypulse.utils.http.socket.gethostbyname", return_value="1.2.3.4"):
        yield
    reset_http_state()