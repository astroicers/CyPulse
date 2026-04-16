"""CyPulse — 開源 EASM 資安曝險評級平台。

`__version__` 從 package metadata 動態讀取，避免與 pyproject.toml 漂移。
開發環境（非 pip install）fallback 讀 pyproject.toml。
"""
from __future__ import annotations


def _read_version() -> str:
    try:
        from importlib.metadata import version
        return version("cypulse")
    except Exception:
        pass
    # 開發模式 fallback：直接讀 pyproject.toml
    try:
        from pathlib import Path
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib
        pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
        if pyproject.is_file():
            return tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]
    except Exception:
        pass
    return "0.0.0-unknown"


__version__ = _read_version()
