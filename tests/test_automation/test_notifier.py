from unittest.mock import patch, MagicMock
from cypulse.automation.notifier import SlackNotifier, EmailNotifier, LineNotifier


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
