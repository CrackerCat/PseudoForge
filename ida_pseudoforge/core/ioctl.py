from __future__ import annotations

import re
from dataclasses import dataclass


IOCTL_METHOD_NAMES = {
    0: "METHOD_BUFFERED",
    1: "METHOD_IN_DIRECT",
    2: "METHOD_OUT_DIRECT",
    3: "METHOD_NEITHER",
}

IOCTL_ACCESS_NAMES = {
    0: "FILE_ANY_ACCESS",
    1: "FILE_READ_ACCESS",
    2: "FILE_WRITE_ACCESS",
    3: "FILE_READ_ACCESS | FILE_WRITE_ACCESS",
}

_INTEGER_SUFFIX_RE = re.compile(r"(?i)(?:ui64|i64|u?ll|llu|ul|lu|u|l)$")


@dataclass(frozen=True)
class IoctlCode:
    value: int
    device_type: int
    function: int
    method: int
    access: int

    @property
    def method_name(self) -> str:
        return IOCTL_METHOD_NAMES[self.method]

    @property
    def access_name(self) -> str:
        return IOCTL_ACCESS_NAMES[self.access]


def parse_c_integer_literal(literal: str) -> int | None:
    token = (literal or "").strip()
    if not token:
        return None
    token = _INTEGER_SUFFIX_RE.sub("", token)
    try:
        return int(token, 0)
    except ValueError:
        return None


def decode_ioctl_code(value: int) -> IoctlCode | None:
    if value < 0x10000 or value > 0xFFFFFFFF:
        return None
    device_type = (value >> 16) & 0xFFFF
    function = (value >> 2) & 0xFFF
    method = value & 0x3
    access = (value >> 14) & 0x3
    if device_type == 0:
        return None
    return IoctlCode(
        value=value,
        device_type=device_type,
        function=function,
        method=method,
        access=access,
    )


def format_ctl_code(value: int) -> str:
    decoded = decode_ioctl_code(value)
    if decoded is None:
        return ""
    return "CTL_CODE(0x%X, 0x%X, %s, %s)" % (
        decoded.device_type,
        decoded.function,
        decoded.method_name,
        decoded.access_name,
    )


def format_ctl_code_from_literal(literal: str) -> str:
    value = parse_c_integer_literal(literal)
    if value is None:
        return ""
    return format_ctl_code(value)


def looks_like_ioctl_dispatcher_name(name: str) -> bool:
    compact = re.sub(r"[^A-Za-z0-9]", "", name or "").lower()
    return compact in {"iocontrolcode", "ioctlcode"} or compact.endswith("iocontrolcode")
