from __future__ import annotations

from contextlib import contextmanager
import os
import queue
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from pathlib import Path


_LOG_QUEUE: queue.Queue[str] = queue.Queue(maxsize=4096)
_DROP_LOCK = threading.Lock()
_TIMER_LOCK = threading.Lock()
_DROP_COUNT = 0
_TIMER = None
_TIMER_STOP_REQUESTED = False
_TIMER_INTERVAL_MS = 250
_MAX_DRAIN_LINES = 64
_DEFAULT_LOG_MAX_BYTES = 1024 * 1024
_MIN_LOG_MAX_BYTES = 64 * 1024
_LOG_MAX_BYTES_ENV = "PSEUDOFORGE_LOG_MAX_BYTES"


def start_output_logger() -> None:
    global _TIMER_STOP_REQUESTED
    _TIMER_STOP_REQUESTED = False
    if _output_logging_disabled():
        _write_trace_line("[PseudoForge] output.timer.disabled")
        return
    _ensure_output_timer()


def stop_output_logger() -> None:
    global _TIMER_STOP_REQUESTED
    _TIMER_STOP_REQUESTED = True
    _unregister_output_timer()


def log_event(message: str) -> None:
    line = ("[PseudoForge] %s" % message).encode("ascii", errors="replace").decode("ascii")
    _write_trace_line(line)


def log_output(message: str) -> None:
    line = ("[PseudoForge] %s" % message).encode("ascii", errors="replace").decode("ascii")
    _write_trace_line(line)
    if _output_logging_disabled():
        return
    try:
        _LOG_QUEUE.put_nowait(line)
    except queue.Full:
        _increment_drop_count()
    _ensure_output_timer_if_main_thread()


def log_checkpoint(event: str, **fields) -> None:
    log_event(_format_checkpoint(event, fields))


@contextmanager
def trace_scope(event: str, **fields) -> Iterator[None]:
    log_checkpoint(event + ".before", **fields)
    try:
        yield
    except Exception as exc:
        log_checkpoint(event + ".failed", error=str(exc), **fields)
        raise
    else:
        log_checkpoint(event + ".after", **fields)


def flush_output_logger() -> None:
    try:
        import ida_kernwin  # type: ignore

        if _is_main_thread(ida_kernwin):
            _drain_queue_to_ida_output()
    except Exception:
        pass


def _ensure_output_timer_if_main_thread() -> None:
    try:
        import ida_kernwin  # type: ignore

        if _is_main_thread(ida_kernwin):
            _ensure_output_timer()
    except Exception:
        pass


def _ensure_output_timer() -> None:
    global _TIMER
    if _TIMER is not None:
        return
    with _TIMER_LOCK:
        if _TIMER is not None:
            return
        try:
            import ida_kernwin  # type: ignore

            register_timer = getattr(ida_kernwin, "register_timer", None)
            if not callable(register_timer):
                return
            timer = register_timer(_TIMER_INTERVAL_MS, _output_timer_callback)
            if timer is not None:
                _TIMER = timer
                _write_trace_line("[PseudoForge] output.timer.started interval_ms=%d" % _TIMER_INTERVAL_MS)
        except Exception as exc:
            _write_trace_line("[PseudoForge] output.timer.start_failed error=\"%s\"" % _ascii_for_log(str(exc)))


def _unregister_output_timer() -> None:
    global _TIMER
    with _TIMER_LOCK:
        timer = _TIMER
        _TIMER = None
    if timer is None:
        return
    try:
        import ida_kernwin  # type: ignore

        unregister_timer = getattr(ida_kernwin, "unregister_timer", None)
        if callable(unregister_timer):
            unregister_timer(timer)
            _write_trace_line("[PseudoForge] output.timer.stopped")
    except Exception as exc:
        _write_trace_line("[PseudoForge] output.timer.stop_failed error=\"%s\"" % _ascii_for_log(str(exc)))


def _output_timer_callback() -> int:
    try:
        _drain_queue_to_ida_output()
    except Exception as exc:
        _write_trace_line("[PseudoForge] output.timer.failed error=\"%s\"" % _ascii_for_log(str(exc)))
    if _TIMER_STOP_REQUESTED:
        return -1
    return _TIMER_INTERVAL_MS


def _drain_queue_to_ida_output() -> None:
    try:
        import ida_kernwin  # type: ignore

        batch = []
        try:
            while len(batch) < _MAX_DRAIN_LINES:
                batch.append(_LOG_QUEUE.get_nowait())
        except queue.Empty:
            pass

        dropped = _take_drop_count()
        if dropped:
            batch.append("[PseudoForge] log.drop count=%d" % dropped)

        if not batch:
            return
        ida_kernwin.msg("\n".join(batch) + "\n")
    except Exception:
        if os.environ.get("PSEUDOFORGE_LOG_STDERR") == "1":
            _drain_queue_to_stderr()


def _drain_queue_to_stderr() -> None:
    batch = []
    try:
        while len(batch) < _MAX_DRAIN_LINES:
            batch.append(_LOG_QUEUE.get_nowait())
    except queue.Empty:
        pass
    if batch:
        sys.stderr.write("\n".join(batch) + "\n")


def _increment_drop_count() -> None:
    global _DROP_COUNT
    with _DROP_LOCK:
        _DROP_COUNT += 1


def _take_drop_count() -> int:
    global _DROP_COUNT
    with _DROP_LOCK:
        value = _DROP_COUNT
        _DROP_COUNT = 0
    return value


def _is_main_thread(ida_kernwin) -> bool:
    is_main_thread = getattr(ida_kernwin, "is_main_thread", None)
    if callable(is_main_thread):
        try:
            return bool(is_main_thread())
        except Exception:
            return False
    return False


def _output_logging_disabled() -> bool:
    return os.environ.get("PSEUDOFORGE_DISABLE_OUTPUT_LOG") == "1"


def _format_checkpoint(event: str, fields: dict[str, object]) -> str:
    parts = ["trace", _ascii_for_log(event)]
    for key, value in fields.items():
        parts.append("%s=%s" % (_ascii_for_log(str(key)), _ascii_for_log(str(value))))
    return " ".join(parts)


def _write_trace_line(line: str) -> None:
    try:
        path = Path(tempfile.gettempdir()) / "pseudoforge_trace.log"
        append_bounded_log_line(path, "%0.3f %s" % (time.time(), line))
    except Exception:
        pass


def append_bounded_log_line(path: str | Path, line: str, max_bytes: int | None = None) -> None:
    log_path = Path(path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    limit = _bounded_log_limit(max_bytes)
    data = _bounded_log_data(line, limit)
    _rotate_log_if_needed(log_path, limit, len(data))
    with log_path.open("ab") as file:
        file.write(data)


def _bounded_log_limit(max_bytes: int | None) -> int:
    if max_bytes is not None:
        return max(int(max_bytes), 1)
    raw_value = os.environ.get(_LOG_MAX_BYTES_ENV, "")
    try:
        value = int(raw_value) if raw_value else _DEFAULT_LOG_MAX_BYTES
    except ValueError:
        value = _DEFAULT_LOG_MAX_BYTES
    return max(value, _MIN_LOG_MAX_BYTES)


def _bounded_log_data(line: str, max_bytes: int) -> bytes:
    data = (line.rstrip("\r\n") + "\n").encode("utf-8", errors="replace")
    if len(data) <= max_bytes:
        return data
    return data[-max_bytes:]


def _rotate_log_if_needed(path: Path, max_bytes: int, incoming_bytes: int) -> None:
    try:
        current_size = path.stat().st_size if path.exists() else 0
        if current_size + incoming_bytes <= max_bytes:
            return
        rotated_path = path.with_name(path.name + ".1")
        if rotated_path.exists():
            rotated_path.unlink()
        path.replace(rotated_path)
    except Exception:
        pass


def _ascii_for_log(value: str) -> str:
    return value.encode("ascii", errors="replace").decode("ascii")
