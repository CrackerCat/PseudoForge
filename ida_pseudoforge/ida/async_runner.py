from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

from ida_pseudoforge.ida.thread_helpers import run_on_main_thread
from ida_pseudoforge.ida.ui_preview import warning
from ida_pseudoforge.logging import log_checkpoint, log_event, log_output


_ACTIVE_TASKS: set[str] = set()
_ACTIVE_GROUPS: dict[str, str] = {}
_ACTIVE_LOCK = threading.Lock()


def run_background(
    task_name: str,
    work: Callable[[], Any],
    on_success: Callable[[Any], None] | None = None,
    group_name: str | None = None,
) -> bool:
    log_checkpoint("background.run.before", task=task_name)
    active_group = group_name or ""
    with _ACTIVE_LOCK:
        if task_name in _ACTIVE_TASKS:
            log_event("%s.skip already_running=true" % task_name)
            log_output("PseudoForge %s is already running." % task_name)
            log_checkpoint("background.run.after", task=task_name, skipped=True)
            return False
        if active_group and active_group in _ACTIVE_GROUPS:
            running_task = _ACTIVE_GROUPS[active_group]
            log_event("%s.skip group_running=%s" % (task_name, running_task))
            log_output("PseudoForge %s is already running. Please wait..." % running_task)
            log_checkpoint("background.run.after", task=task_name, skipped=True, group=active_group)
            return False
        _ACTIVE_TASKS.add(task_name)
        if active_group:
            _ACTIVE_GROUPS[active_group] = task_name

    log_event("%s.queued" % task_name)
    log_checkpoint("background.thread.create.before", task=task_name)

    def runner() -> None:
        log_checkpoint("background.worker.before", task=task_name)
        log_event("%s.worker.start" % task_name)
        try:
            result = work()
        except Exception as exc:
            error_text = str(exc)
            log_event("%s.worker.failed error=\"%s\"" % (task_name, _ascii_for_log(error_text)))
            log_output("PseudoForge %s failed: %s" % (task_name, _ascii_for_log(error_text)))

            def show_error() -> None:
                warning("PseudoForge %s failed: %s" % (task_name, error_text))

            try:
                log_checkpoint("background.error_delivery.before", task=task_name)
                run_on_main_thread(show_error, write=False)
                log_checkpoint("background.error_delivery.after", task=task_name)
            except Exception as ui_exc:
                log_event("%s.error_delivery.failed error=\"%s\"" % (task_name, _ascii_for_log(str(ui_exc))))
            _mark_done(task_name, active_group)
            log_checkpoint("background.worker.after", task=task_name, failed=True)
            return

        log_event("%s.worker.done" % task_name)
        if on_success is None:
            _mark_done(task_name, active_group)
            log_checkpoint("background.worker.after", task=task_name)
            return

        def deliver_success() -> None:
            try:
                log_checkpoint("background.success_callback.before", task=task_name)
                on_success(result)
                log_checkpoint("background.success_callback.after", task=task_name)
            finally:
                _mark_done(task_name, active_group)

        try:
            log_checkpoint("background.success_delivery.before", task=task_name)
            run_on_main_thread(deliver_success, write=False)
            log_checkpoint("background.success_delivery.after", task=task_name)
        except Exception as ui_exc:
            log_event("%s.success_delivery.failed error=\"%s\"" % (task_name, _ascii_for_log(str(ui_exc))))
            _mark_done(task_name, active_group)
            log_checkpoint("background.success_delivery.failed", task=task_name, error=str(ui_exc))
        log_checkpoint("background.worker.after", task=task_name)

    thread = threading.Thread(
        target=runner,
        name="PseudoForge-%s" % task_name,
        daemon=True,
    )
    thread.start()
    log_checkpoint("background.thread.create.after", task=task_name)
    log_checkpoint("background.run.after", task=task_name, skipped=False)
    return True


def _mark_done(task_name: str, group_name: str = "") -> None:
    with _ACTIVE_LOCK:
        _ACTIVE_TASKS.discard(task_name)
        if group_name and _ACTIVE_GROUPS.get(group_name) == task_name:
            del _ACTIVE_GROUPS[group_name]


def active_group_task(group_name: str) -> str:
    with _ACTIVE_LOCK:
        return _ACTIVE_GROUPS.get(group_name, "")


def _ascii_for_log(message: str) -> str:
    return message.encode("ascii", errors="replace").decode("ascii")
