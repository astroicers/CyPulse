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
