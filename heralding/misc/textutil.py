import re

_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def decode_lossless(data: bytes | bytearray | str) -> str:
    """UTF-8 decode that never raises and never loses bytes (backslashreplace)."""
    if isinstance(data, str):
        return data
    return bytes(data).decode("utf-8", errors="backslashreplace")


def sanitize_for_syslog(text: str) -> str:
    return _CTRL.sub(lambda m: repr(m.group())[1:-1], text)
