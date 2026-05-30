from __future__ import annotations

from ida_pseudoforge.logging import log_event


class ActionRegistry:
    def __init__(self, idaapi_module) -> None:
        self._idaapi = idaapi_module
        self._registered: list[str] = []

    @property
    def registered_actions(self) -> tuple[str, ...]:
        return tuple(self._registered)

    def register(self, action_name, label, handler, hotkey, tooltip) -> bool:
        try:
            self._idaapi.unregister_action(action_name)
        except Exception:
            pass
        action = self._idaapi.action_desc_t(action_name, label, handler, hotkey, tooltip, -1)
        try:
            ok = bool(self._idaapi.register_action(action))
        except Exception as exc:
            log_event("action.register.failed name=%s error=\"%s\"" % (action_name, _ascii_for_log(str(exc))))
            return False
        if ok and action_name not in self._registered:
            self._registered.append(action_name)
        log_event("action.register name=%s ok=%d" % (action_name, int(ok)))
        return ok

    def attach_menu(self, menu_path: str, action_name: str) -> bool:
        try:
            ok = bool(self._idaapi.attach_action_to_menu(menu_path, action_name, self._idaapi.SETMENU_APP))
        except Exception as exc:
            log_event(
                "action.attach_menu.failed path=\"%s\" name=%s error=\"%s\""
                % (_ascii_for_log(menu_path), action_name, _ascii_for_log(str(exc)))
            )
            return False
        log_event("action.attach_menu path=\"%s\" name=%s ok=%d" % (_ascii_for_log(menu_path), action_name, int(ok)))
        return ok

    def unregister_all(self) -> None:
        for action_name in reversed(self._registered):
            try:
                ok = bool(self._idaapi.unregister_action(action_name))
            except Exception as exc:
                log_event("action.unregister.failed name=%s error=\"%s\"" % (action_name, _ascii_for_log(str(exc))))
                continue
            log_event("action.unregister name=%s ok=%d" % (action_name, int(ok)))
        self._registered.clear()


def _ascii_for_log(message: str) -> str:
    return message.encode("ascii", errors="replace").decode("ascii")
