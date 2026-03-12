from __future__ import annotations
import os
import structlog


def setup_logging(level: str | None = None) -> None:
    log_level = level or os.environ.get("CYPULSE_LOG_LEVEL", "INFO")
    import logging
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
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
