import grp
import logging
import os
import pwd

logger = logging.getLogger(__name__)


def drop_privileges(user: str = "nobody", group: str | None = "nogroup") -> None:
    """Switch to an unprivileged user once the ports are bound. No-op when not root."""
    if os.getuid() != 0:
        logger.debug("Not running as root, not dropping privileges")
        return
    pw = pwd.getpwnam(user)
    gid = None
    for candidate in (group, "nogroup", "nobody"):
        if not candidate:
            continue
        try:
            gid = grp.getgrnam(candidate).gr_gid
            break
        except KeyError:
            continue
    if gid is None:
        gid = pw.pw_gid
    os.setgroups([])
    os.setgid(gid)
    os.setuid(pw.pw_uid)
    logger.info(
        "Privileges dropped, running as %s/%s",
        pwd.getpwuid(os.getuid()).pw_name,
        grp.getgrgid(os.getgid()).gr_name,
    )
