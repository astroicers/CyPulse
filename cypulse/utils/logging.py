from __future__ import annotations
import os
import re
import structlog


# 含這些字眼的 field name 視為敏感，值會被 mask
_SENSITIVE_KEY_PATTERN = re.compile(
    r"(api[_-]?key|token|password|passwd|secret|webhook|authorization|bearer)",
    re.IGNORECASE,
)


def _mask_value(value: str) -> str:
    """敏感值 mask 規則：
    - 長度 > 8：保留前 4 字 + '***'（便於 debug 比對）
    - 長度 ≤ 8：整個變 '***'（避免短 token 被輕易猜出）
    """
    if not isinstance(value, str):
        return value
    if len(value) > 8:
        return f"{value[:4]}***"
    return "***"


def _mask_secrets(logger, method_name, event_dict):
    """structlog processor：遞迴掃描 event_dict，mask 敏感欄位的值。

    觸發條件：
    - dict key 名稱（任一層）含 SENSITIVE_KEY_PATTERN
      → 該 key 對應的 value 被 mask（含 nested dict/list）
    - list 中元素若前一個元素含 SENSITIVE 字眼（典型 cmd args 模式 [..., "--token", "secret"]）
      → 後一個元素被 mask
    """
    return _mask_recursive(event_dict)


def _mask_recursive(obj, parent_key_sensitive: bool = False):
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            key_sensitive = bool(_SENSITIVE_KEY_PATTERN.search(str(k)))
            if key_sensitive and isinstance(v, str):
                out[k] = _mask_value(v)
            else:
                out[k] = _mask_recursive(v, parent_key_sensitive=key_sensitive)
        return out
    if isinstance(obj, list):
        out = []
        prev_sensitive = parent_key_sensitive
        for item in obj:
            if isinstance(item, str):
                if prev_sensitive:
                    # 前一個元素是 --token 之類，這個就是值
                    out.append(_mask_value(item))
                    prev_sensitive = False
                else:
                    # 檢查當前 string 本身是否含 sensitive 關鍵字
                    out.append(item)
                    prev_sensitive = bool(_SENSITIVE_KEY_PATTERN.search(item))
            else:
                out.append(_mask_recursive(item))
                prev_sensitive = False
        return out
    return obj


def setup_logging(level: str | None = None) -> None:
    log_level = level or os.environ.get("CYPULSE_LOG_LEVEL", "INFO")
    import logging
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    # 設定標準 logging（控制 weasyprint/fontTools 等第三方庫的日誌等級）
    logging.basicConfig(
        level=numeric_level,
        format="%(levelname)s:%(name)s:%(message)s",
        force=True,
    )
    for noisy_lib in ("weasyprint", "fontTools", "fontTools.subset", "fontTools.ttLib"):
        logging.getLogger(noisy_lib).setLevel(logging.ERROR)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            _mask_secrets,  # 在 renderer 之前過濾敏感欄位
            structlog.processors.StackInfoRenderer(),
            structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
