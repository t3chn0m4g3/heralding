"""Minimal BER (ASN.1) reader/writer for the LDAP capability.

Only what LDAP bind/search/unbind need: definite lengths, nested sequences, integers,
octet strings, enumerations and context-specific tags. Everything is length-bounded.
"""

MAX_MESSAGE = 64 * 1024
MAX_DEPTH = 16


class BerError(ValueError):
    pass


class Element:
    __slots__ = ("tag", "value", "depth")

    def __init__(self, tag: int, value: bytes, depth: int = 0):
        self.tag = tag
        self.value = value
        self.depth = depth

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    @property
    def tag_class(self) -> int:
        return self.tag & 0xC0

    @property
    def tag_number(self) -> int:
        return self.tag & 0x1F

    def as_int(self) -> int:
        if not self.value:
            raise BerError("empty integer")
        return int.from_bytes(self.value, "big", signed=True)

    def children(self, depth: int | None = None) -> list[Element]:
        depth = self.depth if depth is None else max(depth, self.depth)
        if depth > MAX_DEPTH:
            raise BerError("nesting too deep")
        return decode_all(self.value, depth + 1)


def read_length(data: bytes, pos: int) -> tuple[int, int]:
    """Return (length, new_pos); long-form lengths up to 4 bytes."""
    if pos >= len(data):
        raise BerError("truncated length")
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    count = first & 0x7F
    if count == 0 or count > 4:
        raise BerError("unsupported length encoding")
    if pos + count > len(data):
        raise BerError("truncated length")
    length = int.from_bytes(data[pos : pos + count], "big")
    if length > MAX_MESSAGE:
        raise BerError("element too large")
    return length, pos + count


def decode_one(data: bytes, pos: int = 0, depth: int = 0) -> tuple[Element, int]:
    if depth > MAX_DEPTH:
        raise BerError("nesting too deep")
    if pos >= len(data):
        raise BerError("truncated element")
    tag = data[pos]
    if tag & 0x1F == 0x1F:
        raise BerError("multi-byte tags not supported")
    length, pos = read_length(data, pos + 1)
    end = pos + length
    if end > len(data):
        raise BerError("truncated value")
    element = Element(tag, data[pos:end], depth)
    if element.constructed:
        decode_all(element.value, depth + 1)
    return element, end


def decode_all(data: bytes, depth: int = 0) -> list[Element]:
    if depth > MAX_DEPTH:
        raise BerError("nesting too deep")
    elements = []
    pos = 0
    while pos < len(data):
        element, pos = decode_one(data, pos, depth)
        elements.append(element)
        if len(elements) > 256:
            raise BerError("too many elements")
    return elements


def encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def encode(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + encode_length(len(value)) + value


def integer(value: int, tag: int = 0x02) -> bytes:
    body = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big", signed=True)
    return encode(tag, body)


def enumerated(value: int) -> bytes:
    return integer(value, 0x0A)


def octet_string(value: bytes | str, tag: int = 0x04) -> bytes:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return encode(tag, value)


def sequence(*parts: bytes, tag: int = 0x30) -> bytes:
    return encode(tag, b"".join(parts))


def set_of(*parts: bytes) -> bytes:
    return encode(0x31, b"".join(parts))
