# Copyright (C) 2019 Sudipta Pandit <realsdx@protonmail.com>
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

import asyncio
import logging
import struct

from heralding.capabilities.handlerbase import HandlerBase
from heralding.libs.msrdp.parser import (
    ClientInfoPDU,
    ErectDomainRequestPDU,
    InvalidExpectedData,
    MCSChannelJoinRequestPDU,
    tpktPDUParser,
    x224ConnectionRequestPDU,
)
from heralding.libs.msrdp.pdu import (
    MCSAttachUserConfirmPDU,
    MCSChannelJoinConfirmPDU,
    MCSConnectResponsePDU,
    x224ConnectionConfirmPDU,
)
from heralding.libs.msrdp.security import ServerSecurity
from heralding.libs.msrdp.tls import TLS, TLSHandshakeError
from heralding.misc import certs

logger = logging.getLogger(__name__)


class RDP(HandlerBase):
    NAME = "rdp"
    NEEDS_CERT = True  # TLS is negotiated inside the RDP flow (libs/msrdp/tls.py)

    # will parse the TPKT header and read the entire packet (TPKT + payload)
    async def recv_next_tpkt(self, reader, tlsObj=None):
        # data buffer
        data = b""
        if tlsObj:
            # read TPKT header
            data += await tlsObj.read_tls(4)
            tpkt = tpktPDUParser()
            tpkt.parse(data)
            # calculate the remaining bytes we need to read
            read_len = tpkt.length - 4
            # read remaining byets
            data += await tlsObj.read_tls(read_len)
        else:
            data = await reader.read(2048)

        return data

    async def send_data(self, writer, data, tlsObj=None):
        if tlsObj:
            await tlsObj.write_tls(data)
            return
        writer.write(data)
        await writer.drain()

    async def execute_capability(self, reader, writer, session):
        try:
            await self._handle_session(reader, writer, session)
        except struct.error as exc:
            logger.debug("RDP connection error: %s", exc)
            session.end_session()

    async def _handle_session(self, reader, writer, session):
        try:
            data = await self.recv_next_tpkt(reader)
            cr_pdu = x224ConnectionRequestPDU()
            cr_pdu.parse(data)

            client_reqProto = 1  # set default to tls
            if cr_pdu.reqProtocols:
                client_reqProto = cr_pdu.reqProtocols
            else:
                # if no nego request was made, then it is rdp security
                client_reqProto = 0

            cc_pdu_obj = x224ConnectionConfirmPDU(client_reqProto)
            cc_pdu = cc_pdu_obj.getFullPacket()
            await self.send_data(writer, cc_pdu)
            if cc_pdu_obj.sentNegoFail:
                logger.debug("Sent x224 RDP Negotiation Failure PDU")
                session.end_session()
                return
            logger.debug("Sent x244CLinetConnectionConfirm PDU")

            # TLS Upgrade start
            logger.debug("RDP TLS initilization")
            pem_file = certs.ensure_cert(
                "rdp.pem", (self.options.get("protocol_specific_data") or {}).get("cert")
            )
            tls_obj = TLS(
                writer, reader, pem_file, min_version=self.persona_value("tls_min_version", "TLSv1")
            )
            await tls_obj.do_tls_handshake()

            # Now using send_data and recv_next_tpkt
            data = await self.recv_next_tpkt(reader, tls_obj)

            # This packet includes ServerSecurity data
            server_sec = ServerSecurity()
            mcs_cres = MCSConnectResponsePDU(client_reqProto, server_sec).getFullPacket()
            await self.send_data(writer, mcs_cres, tls_obj)

            data = await self.recv_next_tpkt(reader, tls_obj)
            if not data:
                logger.debug("Expected ErectDomainRequest. Got Nothing.")
                return
            if not ErectDomainRequestPDU.checkPDU(data):
                logger.debug("Malformed Packet Received. Expected ErectDomainRequest.")
                session.end_session()
                return

            logger.debug("Received: ErectDomainRequest" + repr(data))

            data = await self.recv_next_tpkt(reader, tls_obj)
            logger.debug("Received: Attach User request : " + repr(data))

            mcs_usrcnf = MCSAttachUserConfirmPDU().getFullPacket()
            await self.send_data(writer, mcs_usrcnf, tls_obj)
            logger.debug("Sent: Attach User Confirm")

            # Handle multiple Channel Join request PUDs
            for _ in range(7):
                # data = await reader.read(2048)
                data = await self.recv_next_tpkt(reader, tls_obj)
                if not data:
                    logger.debug("Expected: Channel Join/Client Security Packet.Got Nothing.")
                    return
                channel_req = MCSChannelJoinRequestPDU()
                v = channel_req.parse(data)
                if v < 0:
                    break
                channel_id = channel_req.channelID
                channel_init = channel_req.initiator
                channel_cnf = MCSChannelJoinConfirmPDU(channel_init, channel_id).getFullPacket()

                await self.send_data(writer, channel_cnf, tls_obj)
                logger.debug(f"Sent: MCS Channel Join Confirm of channel {channel_id}")

            # Handle Client Security Exchange PDU
            if not data:
                data = await self.recv_next_tpkt(reader, tls_obj)

            # There is no client security exchange in TLS Security
            client_info = ClientInfoPDU()
            client_info.parseTLS(data)
            username = client_info.rdpUsername
            password = client_info.rdpPassword
            session.set_auxiliary_data(
                {"domain": client_info.domain, "tls_version": tls_obj.version}
            )
            session.add_auth_attempt("plaintext", username=username, password=password)

            session.end_session()
        except InvalidExpectedData, TLSHandshakeError, asyncio.IncompleteReadError:
            logger.debug("Malformed packet detected. Closing session.")
            session.end_session()
            return
