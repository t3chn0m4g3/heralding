from heralding.tests.conftest import make_options

# RDP logins are verified manually with xfreerdp (see the milestone C plan, rule 5);
# robustness is covered by test_fuzz.py.


def _rdp_options(**extra):
    return make_options(
        banner="",
        cert={
            "common_name": "*",
            "country": "US",
            "state": "None",
            "locality": "None",
            "organization": "None",
            "organizational_unit": "None",
            "valid_days": 365,
            "serial_number": 0,
        },
        **extra,
    )


def test_tls_server_data_has_no_proprietary_rsa_material():
    import struct

    from heralding.libs.msrdp.pdu import ServerData

    # Inspect generated server data only; client wire validation uses FreeRDP.
    data = ServerData.generate(1, channel_count=4)
    pos = 0
    blocks = {}
    while pos < len(data):
        kind, length = struct.unpack_from("<HH", data, pos)
        blocks[kind] = data[pos : pos + length]
        pos += length
    assert len(blocks[0x0C02]) == 12
    assert struct.unpack_from("<II", blocks[0x0C02], 4) == (0, 0)
    assert struct.unpack_from("<HH", blocks[0x0C03], 4) == (1003, 4)
    assert struct.unpack_from("<4H", blocks[0x0C03], 8) == (1004, 1005, 1006, 1007)
