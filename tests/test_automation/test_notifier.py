import smtplib
from unittest.mock import patch, MagicMock
from cypulse.automation.notifier import SlackNotifier, EmailNotifier, LineNotifier, send_alerts


class TestSlackNotifier:
    def test_no_webhook(self):
        n = SlackNotifier(webhook_url="")
        assert n.send("test") is False

    @patch("cypulse.automation.notifier.requests.post")
    def test_send_success(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)
        n = SlackNotifier(webhook_url="https://hooks.slack.com/test")
        assert n.send("hello", "info") is True
        mock_post.assert_called_once()


class TestLineNotifier:
    def test_no_token(self):
        n = LineNotifier(token="")
        assert n.send("test") is False


class TestEmailNotifier:
    def test_not_configured(self):
        n = EmailNotifier()
        assert n.send("test") is False


class TestSlackNotifierNon200:
    @patch("cypulse.automation.notifier.requests.post")
    def test_slack_non_200_response(self, mock_post):
        """Slack webhook 回傳非 200 時，send 回傳 False。"""
        mock_post.return_value = MagicMock(status_code=400)
        n = SlackNotifier(webhook_url="https://hooks.slack.com/test")
        assert n.send("alert", "high") is False


class TestLineNotifierNon200:
    @patch("cypulse.automation.notifier.requests.post")
    def test_line_non_200_response(self, mock_post):
        """LINE API 回傳非 200 時，send 回傳 False。"""
        mock_post.return_value = MagicMock(status_code=401)
        n = LineNotifier(token="dummy-token")
        assert n.send("alert", "high") is False


class TestEmailNotifierFull:
    @patch("cypulse.automation.notifier.smtplib.SMTP")
    def test_email_smtp_exception(self, mock_smtp):
        """SMTP 拋出例外時，send 回傳 False，不崩潰。"""
        mock_smtp.side_effect = smtplib.SMTPException("connection refused")
        with patch.dict("os.environ", {
            "EMAIL_SMTP_HOST": "smtp.example.com",
            "EMAIL_FROM": "from@example.com",
            "EMAIL_TO": "to@example.com",
        }):
            n = EmailNotifier()
            assert n.send("test alert", "high") is False

    @patch("cypulse.automation.notifier.smtplib.SMTP")
    def test_email_send_success(self, mock_smtp):
        """SMTP 正常時，send 回傳 True。"""
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp.return_value.__exit__ = MagicMock(return_value=False)
        with patch.dict("os.environ", {
            "EMAIL_SMTP_HOST": "smtp.example.com",
            "EMAIL_FROM": "from@example.com",
            "EMAIL_TO": "to@example.com",
        }):
            n = EmailNotifier()
            assert n.send("test alert", "high") is True


class TestSendAlerts:
    def test_send_alerts_no_config(self):
        """無任何環境變數時，send_alerts 不拋例外。"""
        with patch.dict("os.environ", {}, clear=True):
            send_alerts(["critical alert"], {})  # should not raise

    @patch("cypulse.automation.notifier.requests.post")
    def test_send_alerts_with_slack(self, mock_post):
        """配置 Slack 時，send_alerts 應呼叫 Slack webhook。"""
        mock_post.return_value = MagicMock(status_code=200)
        with patch.dict("os.environ", {"SLACK_WEBHOOK_URL": "https://hooks.slack.com/test"}):
            send_alerts(["high severity alert"], {})
        mock_post.assert_called_once()
