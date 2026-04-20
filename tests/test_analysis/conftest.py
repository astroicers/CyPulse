import pytest
from unittest.mock import patch
from cypulse.utils.http import reset_http_state


@pytest.fixture(autouse=True)
def _isolate_http_state():
    """analysis 模組測試預設：
    - 清 cypulse.utils.http 的 module-level state（DNS cache / circuit）
    - 將 socket.gethostbyname 重導到 dummy IP，避免環境 DNS 黑洞
      （如 ip-api.com 在某些 resolver 上回 0.0.0.0）干擾 mock 過 requests.get 的測試
    """
    reset_http_state()
    with patch("cypulse.utils.http.socket.gethostbyname", return_value="1.2.3.4"):
        yield
    reset_http_state()