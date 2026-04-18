"""把常見 Exception 分類並回傳「修復建議」字串。

設計原則：
- 不吃掉原始錯誤資訊；總是含 type + str(exc)
- 已知模式給出具體下一步（指令、檔案路徑、文件連結）
- 未知模式回 fallback「未分類錯誤：<type>: <msg>」

不在 cli.py 直接寫一堆 if/elif，集中管理便於測試與未來擴充。
"""
from __future__ import annotations

import subprocess


_KNOWN_TOOLS = {
    "nuclei", "subfinder", "amass", "dnsx", "httpx", "naabu",
    "nmap", "testssl.sh", "s3scanner",
}


def format_error(exc: BaseException) -> str:
    """將 Exception 轉成使用者友善的修復建議文字。

    回傳格式：「<one-line summary>\n  → <action>」
    """
    # ImportError / ModuleNotFoundError —— 多半是依賴版本問題
    if isinstance(exc, ImportError):
        msg = str(exc)
        if "dns.nameserver" in msg or "dns.name" in msg:
            return (
                "ImportError: dnspython 版本太舊（checkdmarc 需要 2.4+）\n"
                "  → 執行: pip install --upgrade 'dnspython>=2.4'"
            )
        if "checkdmarc" in msg:
            return (
                "ImportError: checkdmarc 未安裝\n"
                "  → 執行: pip install -e .[dev] 或檢查 requirements.txt"
            )
        return (
            f"ImportError: {msg}\n"
            "  → 執行: pip install -e . 重新安裝；或檢查 requirements.txt"
        )

    # subprocess.TimeoutExpired —— 工具執行超時
    if isinstance(exc, subprocess.TimeoutExpired):
        cmd = exc.cmd if isinstance(exc.cmd, str) else (exc.cmd[0] if exc.cmd else "?")
        return (
            f"外部工具 '{cmd}' 執行超時（超過 {exc.timeout}s）\n"
            "  → 增加 config.scan.timeout_seconds，或檢查工具是否能正常執行"
        )

    # requests.Timeout —— 網路 timeout
    try:
        import requests
        if isinstance(exc, requests.Timeout):
            return (
                "HTTP 請求逾時（目標無回應或網路太慢）\n"
                "  → 重試或檢查網路；用 --timeout 增加掃描整體上限"
            )
        if isinstance(exc, requests.ConnectionError):
            return (
                f"HTTP 連線失敗：{exc}\n"
                "  → 檢查網路 / DNS / 目標主機是否可達"
            )
    except ImportError:
        pass

    # FileNotFoundError —— 工具未安裝
    if isinstance(exc, FileNotFoundError):
        # exc.filename 在 Python 3 為「找不到的檔案/工具名」
        target = getattr(exc, "filename", None) or str(exc)
        if isinstance(target, str) and any(t in target for t in _KNOWN_TOOLS):
            return (
                f"找不到工具: {target}\n"
                "  → 請參考 docs/DEPLOY_SPEC.md 安裝；或使用 docker compose run cypulse"
            )
        return (
            f"檔案不存在: {target}\n"
            "  → 確認路徑與權限正確"
        )

    # DiffSchemaError —— 跨版本相容問題
    try:
        from cypulse.automation.diff import DiffSchemaError
        if isinstance(exc, DiffSchemaError):
            return (
                f"差異比對 schema 不相容: {exc}\n"
                "  → 舊版本掃描資料無法與目前版本比對；建議重新掃描以建立新基準"
            )
    except ImportError:
        pass

    # ScanAborted —— 中斷狀態
    try:
        from cypulse.utils.scan_lifecycle import ScanAborted
        if isinstance(exc, ScanAborted):
            return (
                f"掃描已中止: {exc}\n"
                "  → 部分結果可能已保存於 scan_dir；可重新執行掃描"
            )
    except ImportError:
        pass

    # Fallback：未分類
    return f"未預期錯誤 {type(exc).__name__}: {exc}"
