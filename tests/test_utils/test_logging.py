import logging
from cypulse.utils.logging import setup_logging


def test_setup_logging_default():
    setup_logging()
    root_logger = logging.getLogger()
    assert root_logger.level == logging.INFO


def test_setup_logging_debug():
    setup_logging("DEBUG")
    root_logger = logging.getLogger()
    assert root_logger.level == logging.DEBUG


def test_setup_logging_env_var(monkeypatch):
    monkeypatch.setenv("CYPULSE_LOG_LEVEL", "WARNING")
    setup_logging()
    root_logger = logging.getLogger()
    assert root_logger.level == logging.WARNING


def test_setup_logging_noisy_libs_suppressed():
    setup_logging()
    for lib in ("weasyprint", "fontTools"):
        assert logging.getLogger(lib).level == logging.ERROR


class TestMaskSecrets:
    """secret masking processor 測試（Task Q）。"""

    def test_mask_string_value_with_key_in_field_name(self):
        from cypulse.utils.logging import _mask_secrets
        out = _mask_secrets(None, "info", {"api_key": "abcd1234efgh", "msg": "ok"})
        # key 含 "key" → 值被 mask 但保留前 4 字便於比對
        assert out["api_key"].startswith("abcd")
        assert "***" in out["api_key"]
        assert "1234efgh" not in out["api_key"]
        # 一般欄位不動
        assert out["msg"] == "ok"

    def test_mask_token_password_secret_webhook_authorization(self):
        from cypulse.utils.logging import _mask_secrets
        for field in ("token", "password", "secret", "webhook_url", "Authorization"):
            out = _mask_secrets(None, "info", {field: "secretvalue123456"})
            assert "***" in out[field], f"{field} 應被 mask"
            assert "secretvalue" not in out[field][4:], f"{field} 不應暴露完整 secret"

    def test_no_mask_for_normal_short_string(self):
        from cypulse.utils.logging import _mask_secrets
        out = _mask_secrets(None, "info", {"domain": "example.com", "msg": "hello"})
        assert out["domain"] == "example.com"
        assert out["msg"] == "hello"

    def test_mask_in_dict_recursively(self):
        from cypulse.utils.logging import _mask_secrets
        event = {"config": {"API_KEY": "supersecret123456789"}}
        out = _mask_secrets(None, "info", event)
        assert "***" in out["config"]["API_KEY"]
        assert "supersecret" not in out["config"]["API_KEY"][4:]

    def test_mask_in_list_recursively(self):
        from cypulse.utils.logging import _mask_secrets
        # 模擬 run_cmd 的 cmd list：含 --token 後面跟著 secret value
        event = {"cmd": ["nuclei", "--auth-token", "verylongsecrettoken123"]}
        out = _mask_secrets(None, "info", event)
        # cmd list 仍是 list；含 token 字眼後面那個元素應被 mask
        assert isinstance(out["cmd"], list)
        # 至少一個元素被 mask（保守實作：有 "token" 字眼就 mask 後續）
        masked_present = any("***" in x for x in out["cmd"] if isinstance(x, str))
        assert masked_present, f"cmd list 未含 mask: {out['cmd']}"

    def test_case_insensitive_key_matching(self):
        from cypulse.utils.logging import _mask_secrets
        out = _mask_secrets(None, "info", {
            "API_KEY": "abc12345xyz",
            "Webhook_URL": "https://hooks.slack.com/services/T00/B00/secretpath",
        })
        assert "***" in out["API_KEY"]
        assert "***" in out["Webhook_URL"]

    def test_short_value_still_masked_when_key_matches(self):
        """key 含敏感字眼但值很短，仍應 mask（避免短 token 被忽略）。"""
        from cypulse.utils.logging import _mask_secrets
        out = _mask_secrets(None, "info", {"token": "abc"})
        # 太短時用 *** 整個遮罩
        assert out["token"] == "***"


class TestScanIdContextVar:
    """Task T：scan_id 注入 structlog contextvars，貫穿整個 scan 的 log。"""

    def test_bind_scan_id_appears_in_log(self, capsys):
        from cypulse.utils.logging import setup_logging
        import structlog

        setup_logging("INFO")
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(scan_id="abc123def456")
        try:
            log = structlog.get_logger()
            log.info("test_event")
            captured = capsys.readouterr()
            assert "abc123def456" in captured.out
        finally:
            structlog.contextvars.clear_contextvars()

    def test_clear_contextvars_removes_scan_id(self, capsys):
        from cypulse.utils.logging import setup_logging
        import structlog

        setup_logging("INFO")
        structlog.contextvars.bind_contextvars(scan_id="should_not_appear")
        structlog.contextvars.clear_contextvars()
        log = structlog.get_logger()
        log.info("after_clear")
        captured = capsys.readouterr()
        assert "should_not_appear" not in captured.out
