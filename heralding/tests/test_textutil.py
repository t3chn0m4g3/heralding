from heralding.misc.textutil import decode_lossless, sanitize_for_syslog


def test_decode_utf8():
    assert decode_lossless("пайтон".encode()) == "пайтон"


def test_decode_invalid_bytes_are_kept():
    assert decode_lossless(b"pa\xe4ss") == "pa\\xe4ss"


def test_syslog_escapes_control_chars():
    assert sanitize_for_syslog("a\r\nb\x00c") == "a\\r\\nb\\x00c"
