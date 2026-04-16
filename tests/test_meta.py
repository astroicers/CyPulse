"""Meta 守門測試：跨檔案單一事實來源一致性。

這些測試不測 code 行為，而是守門「同一事實在多處定義時必須同步」：
- pyproject.toml version ↔ CHANGELOG.md 最新版本
- GRADES（weights.py）↔ ADR-004 文字閾值
"""
from __future__ import annotations

import re
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ImportError:
    import tomli as tomllib  # Python 3.10 fallback

from cypulse.scoring.weights import GRADES

ROOT = Path(__file__).resolve().parents[1]


def test_pyproject_version_matches_latest_changelog():
    """pyproject.toml 的 version 必須等於 CHANGELOG.md 最上方的版本號。

    避免 PyPI 發布時 version 與 changelog 脫鉤（使用者看到的版本不一致）。
    """
    pyproject_text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    pyproject_version = tomllib.loads(pyproject_text)["project"]["version"]

    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    match = re.search(r"^## \[(\d+\.\d+\.\d+)\]", changelog, re.MULTILINE)
    assert match, "CHANGELOG.md 找不到任何 `## [x.y.z]` 版本標題"
    latest_changelog_version = match.group(1)

    assert pyproject_version == latest_changelog_version, (
        f"pyproject.toml version={pyproject_version} "
        f"與 CHANGELOG 最新版本 {latest_changelog_version} 不一致。"
        " 發新版時務必同時更新兩者。"
    )


def test_package_version_matches_pyproject():
    """cypulse.__version__ 必須與 pyproject.toml version 一致。

    以前 cypulse/__init__.py 硬寫 __version__，與 pyproject 漂移後
    CLI --version 顯示舊值（實測 docker compose run cypulse --version）。
    現改為動態讀 package metadata。
    """
    from cypulse import __version__

    pyproject_text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    pyproject_version = tomllib.loads(pyproject_text)["project"]["version"]

    assert __version__ == pyproject_version, (
        f"cypulse.__version__={__version__} 與 "
        f"pyproject.toml version={pyproject_version} 不一致。"
    )


def test_grades_match_adr004():
    """GRADES（scoring/weights.py）必須與 ADR-004 文字描述的閾值一致。

    ADR-004 將等級閾值線性化。接受兩種文字格式：
    - 表格 cell：`| A | 90-100 |`
    - inline：`A(90-100)` / `A(90–100)`
    若未來有人調 GRADES 卻忘了更新 ADR-004 或反之，此測試會攔下。
    """
    adr_path = ROOT / "docs/adr/ADR-004-scoring-dedup-and-remediation.md"
    adr_text = adr_path.read_text(encoding="utf-8")

    for grade, (low, high) in GRADES.items():
        range_str_hyphen = f"{low}-{high}"
        range_str_endash = f"{low}–{high}"
        # 表格 cell 格式：`| A | 90-100 |`（注意前後有 |）
        table_hyphen = f"| {grade} | {range_str_hyphen} |"
        table_endash = f"| {grade} | {range_str_endash} |"
        # inline 格式：A(90-100)
        inline_hyphen = f"{grade}({range_str_hyphen})"
        inline_endash = f"{grade}({range_str_endash})"
        found = any(
            pat in adr_text
            for pat in (table_hyphen, table_endash, inline_hyphen, inline_endash)
        )
        assert found, (
            f"GRADES[{grade}]=({low},{high}) 未在 ADR-004 文字中出現。"
            f" 預期找到表格格式 `| {grade} | {range_str_hyphen} |` "
            f"或 inline `{inline_hyphen}`。"
        )
