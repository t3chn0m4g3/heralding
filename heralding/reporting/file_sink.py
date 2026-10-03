import csv
import json
import logging
import os

from heralding.reporting.hub import Sink

logger = logging.getLogger(__name__)

# Column order is part of Heralding's stable public log format.
# New columns may only be appended at the end.
AUTH_FIELDS = (
    "timestamp",
    "auth_id",
    "session_id",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "protocol",
    "username",
    "password",
    "password_hash",
)
SESSION_FIELDS = (
    "timestamp",
    "duration",
    "session_id",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "protocol",
    "num_auth_attempts",
)


class FileSink(Sink):
    name = "file"

    def __init__(self, session_csv_logfile: str, session_json_logfile: str, auth_logfile: str):
        self.paths = {
            "auth": auth_logfile or "",
            "csv": session_csv_logfile or "",
            "json": session_json_logfile or "",
        }
        self._auth_fh = self._csv_fh = self._json_fh = None
        self._auth_writer = self._csv_writer = None

    def open(self) -> None:
        if self.paths["auth"]:
            self._auth_fh, self._auth_writer = self._open_csv(self.paths["auth"], AUTH_FIELDS)
            logger.info(
                "File logger: Using %s to log authentication attempts in CSV format.",
                self.paths["auth"],
            )
        if self.paths["csv"]:
            self._csv_fh, self._csv_writer = self._open_csv(self.paths["csv"], SESSION_FIELDS)
            logger.info(
                "File logger: Using %s to log unified session data in CSV format.",
                self.paths["csv"],
            )
        if self.paths["json"]:
            self._json_fh = open(
                self.paths["json"], "a", encoding="utf-8", errors="surrogateescape"
            )
            logger.info(
                "File logger: Using %s to log complete session data in JSON format.",
                self.paths["json"],
            )

    @staticmethod
    def _open_csv(path, fields):
        fh = open(path, "a", encoding="utf-8", errors="surrogateescape", newline="")
        writer = csv.DictWriter(
            fh, fieldnames=list(fields), extrasaction="ignore", lineterminator="\n"
        )
        # empty file (fresh or after copytruncate): write the header
        if os.path.getsize(path) == 0:
            writer.writeheader()
            fh.flush()
        return fh, writer

    def close(self) -> None:
        for fh in (self._auth_fh, self._csv_fh, self._json_fh):
            if fh is not None:
                fh.flush()
                fh.close()

    def handle_auth(self, data: dict) -> None:
        if self._auth_writer is not None:
            self._auth_writer.writerow(data)
            self._auth_fh.flush()

    def handle_session(self, data: dict) -> None:
        if not data.get("session_ended"):
            return
        if self._csv_writer is not None:
            self._csv_writer.writerow(data)
            self._csv_fh.flush()
        if self._json_fh is not None:
            self._json_fh.write(json.dumps(data, ensure_ascii=False) + "\n")
            self._json_fh.flush()
