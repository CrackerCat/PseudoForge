from __future__ import annotations

from collections.abc import Callable
from typing import Any

try:
    import ida_kernwin  # type: ignore
except Exception:
    ida_kernwin = None


def run_on_main_thread(func: Callable[[], Any], write: bool = False) -> Any:
    if ida_kernwin is None:
        return func()

    is_main_thread = getattr(ida_kernwin, "is_main_thread", None)
    if callable(is_main_thread):
        try:
            if is_main_thread():
                return func()
        except Exception:
            pass

    slot: dict[str, Any] = {}
    flag = ida_kernwin.MFF_WRITE if write else ida_kernwin.MFF_READ

    def runner() -> int:
        try:
            slot["result"] = func()
            slot["ok"] = True
        except Exception as exc:
            slot["error"] = exc
            slot["ok"] = False
        return 1

    ida_kernwin.execute_sync(runner, flag)
    if not slot.get("ok", False):
        error = slot.get("error")
        if isinstance(error, Exception):
            raise error
        raise RuntimeError("IDA main-thread execution failed")
    return slot.get("result")
