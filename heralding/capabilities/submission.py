# Copyright (C) 2026 Heralding contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Message submission (port 587): SMTP with STARTTLS; AUTH is logged before and after TLS."""

from heralding.capabilities.handlerbase import HandlerBase
from heralding.capabilities.smtp import SMTPHandler, smtp


class Submission(smtp):
    NAME = "submission"
    PERSONA_NAME = "smtp"  # banners come from the persona's smtp entry
    TLS = "starttls"
    NEEDS_CERT = True

    async def execute_capability(self, reader, writer, session):
        session.set_auxiliary_data({"starttls": False})
        persona = HandlerBase.persona
        handler = SMTPHandler(
            reader,
            writer,
            session,
            self._options,
            banner=self.persona_value("banner", "ESMTP"),
            ehlo_hostname=persona.fqdn if persona is not None else None,
            tls_context=self.starttls_context,
            fqdn=self.explicit_fqdn,
        )
        await handler._handle_client()
