import random

from spnego._ntlm_raw.messages import AvId, Challenge

from heralding.libs import ntlm
from heralding.misc.persona import select_persona


def _challenge(persona):
    return Challenge.unpack(
        ntlm.challenge_message(
            b"\0" * 8,
            persona.netbios or persona.hostname,
            persona.domain,
            persona.fqdn,
            version=ntlm.parse_version(persona.os_version),
        )
    )


def test_windows_persona_challenge_looks_like_windows():
    persona = select_persona({"persona": "windows-server-2022"}, rng=random.Random(1))
    message = _challenge(persona)  # parsed with the pyspnego client library
    info = message.target_info
    assert message.target_name == "AD"
    assert info[AvId.nb_domain_name] == "AD" and "." not in info[AvId.nb_domain_name]
    assert info[AvId.dns_domain_name] == info[AvId.dns_tree_name] == "ad.local"
    assert info[AvId.dns_computer_name] == persona.fqdn
    assert AvId.timestamp in info
    assert (message.version.major, message.version.minor, message.version.build) == (10, 0, 20348)


def test_linux_persona_reports_a_samba_version():
    persona = select_persona({"persona": "debian-12"}, rng=random.Random(1))
    message = _challenge(persona)
    assert (message.version.major, message.version.minor, message.version.build) == (6, 1, 0)
    assert message.target_name == persona.domain.upper()


def test_netbios_domain_is_bounded():
    assert ntlm.netbios_domain("a-very-long-domain-label.example") == "A-VERY-LONG-DOM"
    assert ntlm.netbios_domain("") == "WORKGROUP"
