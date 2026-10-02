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


def test_server_random_is_random_and_key_is_lazy():
    from heralding.libs.msrdp import security

    a, b = security.ServerSecurity(), security.ServerSecurity()
    assert a.server_random != b.server_random and len(a.server_random) == 32
    assert security.getRSAKeys() is security.getRSAKeys()  # cached, created on first use
