from __future__ import annotations
import os
import structlog


def setup_logging(level: str | None = None) -> None:
    log_level = level or os.environ.get("CYPULSE_LOG_LEVEL", "INFO")
    import logging
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    # 設定標準 logging（控制 weasyprint/fontTools 等第三方庫的日誌等級）
    logging.basicConfig(level=numeric_level, format="%(levelname)s:%(name)s:%(message)s", force=True)
    for noisy_lib in ("weasyprint", "fontTools", "fontTools.subset", "fontTools.ttLib"):
        logging.getLogger(noisy_lib).setLevel(logging.ERROR)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
