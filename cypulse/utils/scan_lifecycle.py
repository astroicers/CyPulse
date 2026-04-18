"""ScanContext — 集中管理掃描執行期 lifecycle。

責任：
- abort flag 與原因記錄（供各 phase 檢查是否該中止）
- temp 檔註冊與一鍵清理（避免 Ctrl-C / timeout 後 /tmp 殘留）
- deadline 計算（供 progress UI 顯示剩餘時間、各 phase 自我檢查）

不直接綁定 signal —— signal handler 由 cli.py 註冊並呼叫 ctx.abort() + ctx.cleanup_temp_files()，
這樣 ScanContext 本身可獨立單元測試（見 ADR-007）。
"""
from __future__ import annotations

import os
import time
from typing import List


class ScanAborted(Exception):
    """掃描已中止（由 timeout 或 SIGINT 觸發）。"""


class ScanContext:
    """掃描生命週期狀態容器。

    Args:
        timeout_seconds: 全局 timeout（秒）。0 = 無 timeout。
    """

    def __init__(self, timeout_seconds: int = 0):
        self.timeout_seconds = timeout_seconds
        self.start_time = time.time()
        self.aborted = False
        self.abort_reason: str | None = None
        self._temp_files: List[str] = []

    @property
    def deadline(self) -> float | None:
        """回傳 Unix epoch deadline；無 timeout 時回 None。"""
        if self.timeout_seconds <= 0:
            return None
        return self.start_time + self.timeout_seconds

    def remaining_seconds(self) -> float | None:
        """剩餘秒數；無 timeout 時 None；已超時回負值。"""
        if self.deadline is None:
            return None
        return self.deadline - time.time()

    def abort(self, reason: str) -> None:
        """標記中止。重複呼叫只保留首次原因。"""
        if not self.aborted:
            self.aborted = True
            self.abort_reason = reason

    def check_aborted(self) -> None:
        """供各 phase 在分段點檢查。已 abort 則拋 ScanAborted。"""
        if self.aborted:
            raise ScanAborted(f"Scan aborted: {self.abort_reason}")

    def register_temp_file(self, path: str) -> None:
        """註冊一個 temp 檔，cleanup 時會被刪除。"""
        self._temp_files.append(path)

    def cleanup_temp_files(self) -> None:
        """刪除所有已註冊的 temp 檔。已不存在的檔案會被靜默忽略。"""
        for path in self._temp_files:
            try:
                os.unlink(path)
            except OSError:
                pass  # 已被刪除或無權限，無視
        self._temp_files.clear()


# Module-level 「目前活躍的 ScanContext」，供 SIGINT handler / 跨層 temp 檔註冊存取。
_active_context: ScanContext | None = None


def set_active_scan_context(ctx: ScanContext | None) -> None:
    """設定/清除目前活躍的 ScanContext。CLI scan 開始時設定，結束時清除。"""
    global _active_context
    _active_context = ctx


def get_active_scan_context() -> ScanContext | None:
    """取得目前活躍的 ScanContext；若無則回 None。

    供 web_security/cloud_exposure 等跨層模組註冊 temp 檔使用。
    """
    return _active_context


def install_sigint_handler(ctx: ScanContext):
    """安裝 SIGINT handler，回傳 handler 函式（便於測試直接呼叫）。

    第一次 SIGINT：abort + cleanup_temp_files，讓主流程的 ScanAborted try/except 接手
    第二次 SIGINT：raise KeyboardInterrupt 強制退出（避免 cleanup 卡住）
    """
    import signal as _signal
    state = {"first_call": True}

    def _handler(signum, frame):
        if state["first_call"]:
            state["first_call"] = False
            ctx.abort(reason="user_interrupt (SIGINT)")
            ctx.cleanup_temp_files()
        else:
            # 第二次：強制離開
            raise KeyboardInterrupt("Forced exit on second SIGINT")

    _signal.signal(_signal.SIGINT, _handler)
    return _handler
