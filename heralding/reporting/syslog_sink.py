import logging
import syslog

from heralding.misc.textutil import sanitize_for_syslog
from heralding.reporting.hub import Sink

logger = logging.getLogger(__name__)


class SyslogSink(Sink):
    name = "syslog"

    def __init__(self, level_name: str = "LOG_ALERT"):
        self.level = getattr(syslog, level_name, syslog.LOG_ALERT)

    def handle_auth(self, data: dict) -> None:
        message = "Authentication from {}:{}, with username: {} and password: {}.".format(
            data["source_ip"],
            data["source_port"],
            sanitize_for_syslog(str(data.get("username"))),
            sanitize_for_syslog(str(data.get("password"))),
        )
        syslog.syslog(self.level, message)
