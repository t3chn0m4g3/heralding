# license: LGPL
# Thanks a lot to the author of original telnetsrvlib - Ian Epperson (https://github.com/ianepperson)!
# Original repository - https://github.com/ianepperson/telnetsrvlib
# We need this in order to reduce the number of third-party modules.
# This code is adjusted to work with asyncio in our specific case.

import asyncio
import logging

from heralding.libs.aiobaserequest import AsyncBaseRequestHandler

log = logging.getLogger(__name__)

# Key codes (values as in curses, kept so the readline logic stays recognisable)
KEY_DOWN = 258
KEY_UP = 259
KEY_LEFT = 260
KEY_RIGHT = 261
KEY_BACKSPACE = 263
KEY_DC = 330

BELL = bytes([7])
ANSI_START_SEQ = b"["
ANSI_KEY_TO_CODE = {
    b"A": KEY_UP,
    b"B": KEY_DOWN,
    b"C": KEY_RIGHT,
    b"D": KEY_LEFT,
}

# Telnet protocol characters (don't change)
IAC = bytes([255])  # "Interpret As Command"
DONT = bytes([254])
DO = bytes([253])
WONT = bytes([252])
WILL = bytes([251])
theNULL = bytes([0])

SE = bytes([240])  # Subnegotiation End
NOP = bytes([241])  # No Operation
SB = bytes([250])  # Subnegotiation Begin

# Telnet protocol options code (don't change)
# These ones all come from arpa/telnet.h
ECHO = bytes([1])  # echo
SGA = bytes([3])  # suppress go ahead
TTYPE = bytes([24])  # terminal type
NAWS = bytes([31])  # window size
LINEMODE = bytes([34])  # Linemode option
NEW_ENVIRON = bytes([39])  # New - Environment variables
NOOPT = bytes([0])

IS = bytes([0])
SEND = bytes([1])


def unctrl(c):
    """Printable representation of a control character (like curses.ascii.unctrl)."""
    if c < 32:
        return "^" + chr(c + 64)
    if c == 127:
        return "^?"
    return chr(c)


class TelnetHandlerBase(AsyncBaseRequestHandler):
    """A telnet server based on the client in telnetlib"""

    # Hard limits against hostile clients
    MAX_LINE = 1024  # bytes per input line; extra bytes are dropped
    MAX_COOKED = 4096  # buffered, not yet consumed input characters

    # What I am prepared to do?
    DOACK = {
        ECHO: WILL,
        SGA: WILL,
        NEW_ENVIRON: WONT,
    }
    # What do I want the client to do?
    WILLACK = {
        ECHO: DONT,
        SGA: DO,
        NAWS: DONT,
        TTYPE: DO,
        LINEMODE: DONT,
        NEW_ENVIRON: DO,
    }
    # Terminal output escape sequences (plain ANSI; no terminfo lookup)
    CODES = {
        "DEOL": b"\x1b[K",  # Delete to end of line
        "DEL": b"\x1b[P",  # Delete and close up
        "INS": b"\x1b[@",  # Insert space
        "CSRLEFT": b"\x1b[D",  # Move cursor left 1 space
        "CSRRIGHT": b"\x1b[C",  # Move cursor right 1 space
    }

    # --------------------------- Environment Setup ----------------------------

    def __init__(self, reader, writer, client_address):
        # Am I doing the echoing?
        self.DOECHO = True
        # What opts have I sent DO/DONT for and what did I send?
        self.DOOPTS = {}
        # What opts have I sent WILL/WONT for and what did I send?
        self.WILLOPTS = {}
        self.reader = reader
        self.writer = writer
        self.rawq = b""  # Raw input string
        self.sbdataq = b""  # Sub-Neg string
        self.eof = 0  # Has EOF been reached?
        self.iacseq = b""  # Buffer for IAC sequence.
        self.sb = 0  # Flag for SB and SE sequence.
        self.history = []  # Command history
        self.cookedq = asyncio.Queue(maxsize=self.MAX_COOKED)
        self.inputcooker_task = None
        super().__init__(reader, writer, client_address)

    def setup(self):
        """Connect incoming connection to a telnet session"""
        for k in self.DOACK.keys():
            self.sendcommand(self.DOACK[k], k)
        for k in self.WILLACK.keys():
            self.sendcommand(self.WILLACK[k], k)
        self.inputcooker_task = asyncio.create_task(self.inputcooker())

    def finish(self):
        """End this session"""
        log.debug("Session disconnected.")
        self.session_end()

    def session_start(self):
        pass

    def session_end(self):
        pass

    # ------------------------- Telnet Options Engine --------------------------

    def sendcommand(self, cmd, opt=None):
        """Send a telnet command (IAC). Only used during setup; flushed by the first drain."""
        if cmd in [DO, DONT]:
            if opt not in self.DOOPTS:
                self.DOOPTS[opt] = None
            if ((cmd == DO) and (self.DOOPTS[opt] is not True)) or (
                (cmd == DONT) and (self.DOOPTS[opt] is not False)
            ):
                self.DOOPTS[opt] = cmd == DO
                self.writer.write(IAC + cmd + opt)
        elif cmd in [WILL, WONT]:
            if opt not in self.WILLOPTS:
                self.WILLOPTS[opt] = b""
            if ((cmd == WILL) and (self.WILLOPTS[opt] is not True)) or (
                (cmd == WONT) and (self.WILLOPTS[opt] is not False)
            ):
                self.WILLOPTS[opt] = cmd == WILL
                self.writer.write(IAC + cmd + opt)
        else:
            self.writer.write(IAC + cmd)

    # ---------------------------- Input Functions -----------------------------

    def _readline_do_echo(self, echo):
        """Determine if we should echo or not"""
        return echo is True or (echo is None and self.DOECHO is True)

    async def _readline_echo(self, char, echo):
        """Echo a received character, move cursor etc..."""
        if self._readline_do_echo(echo):
            await self.write(char)

    _current_line = b""
    _current_prompt = b""

    async def ansi_to_code(self, char):
        """Handles reading ANSI escape sequences"""
        # ANSI sequences are:
        # ESC [ <key>
        if char != 27:  # ESC
            return char
        if convert_to_bytes(await self.getc()) != ANSI_START_SEQ:
            await self._readline_echo(BELL, True)
            return 0
        key = convert_to_bytes(await self.getc())
        try:
            return ANSI_KEY_TO_CODE[key]
        except KeyError:
            await self._readline_echo(BELL, True)
            return 0

    async def _readline_insert(self, charb, echo, insptr, line):
        """Deal properly with inserted chars in a line."""
        if not self._readline_do_echo(echo):
            return
        # Write out the remainder of the line
        await self.write(charb + bytes(line[insptr:]))
        # Cursor Left to the current insert point
        char_count = len(line) - insptr
        await self.write(self.CODES["CSRLEFT"] * char_count)

    async def readline(self, echo=None, prompt=b"", use_history=True):
        """Return a line of bytes, without the terminating LF.
        If echo is true always echo, if echo is false never echo
        If echo is None follow the negotiated setting.
        prompt is the current prompt to write (and rewrite if needed)
        use_history controls if this current line uses (and adds to) the command history.
        Lines longer than MAX_LINE bytes are truncated silently.
        """

        line = []
        insptr = 0
        histptr = len(self.history)

        if self.DOECHO:
            await self.write(prompt)
            self._current_prompt = prompt
        else:
            self._current_prompt = b""

        self._current_line = b""

        while True:
            c = await self.getc()
            c = await self.ansi_to_code(c)
            cb = convert_to_bytes(c)

            if cb == theNULL:
                continue

            elif c == KEY_LEFT:
                if insptr > 0:
                    insptr -= 1
                    await self._readline_echo(self.CODES["CSRLEFT"], echo)
                else:
                    await self._readline_echo(BELL, echo)
                continue
            elif c == KEY_RIGHT:
                if insptr < len(line):
                    insptr += 1
                    await self._readline_echo(self.CODES["CSRRIGHT"], echo)
                else:
                    await self._readline_echo(BELL, echo)
                continue
            elif c == KEY_UP or c == KEY_DOWN:
                if not use_history:
                    await self._readline_echo(BELL, echo)
                    continue
                if c == KEY_UP:
                    if histptr > 0:
                        histptr -= 1
                    else:
                        await self._readline_echo(BELL, echo)
                        continue
                elif c == KEY_DOWN:
                    if histptr < len(self.history):
                        histptr += 1
                    else:
                        await self._readline_echo(BELL, echo)
                        continue
                line = []
                if histptr < len(self.history):
                    line.extend(self.history[histptr])
                for _ in range(insptr):
                    await self._readline_echo(self.CODES["CSRLEFT"], echo)
                await self._readline_echo(self.CODES["DEOL"], echo)
                await self._readline_echo(bytes(line), echo)
                insptr = len(line)
                continue
            elif cb == bytes([3]):
                await self._readline_echo(b"\n" + unctrl(c).encode() + b" ABORT\n", echo)
                return b""
            elif cb == bytes([4]):
                if len(line) > 0:
                    await self._readline_echo(
                        b"\n" + unctrl(c).encode() + b" ABORT (QUIT)\n", echo
                    )
                    return b""
                await self._readline_echo(b"\n" + unctrl(c).encode() + b" QUIT\n", echo)
                return b"QUIT"
            elif cb == bytes([10]):
                await self._readline_echo(cb, echo)
                result = bytes(line)
                if use_history:
                    self.history.append(result)
                if echo is False:
                    if prompt:
                        await self.write(bytes([10]))
                    log.debug("readline: %s(hidden text)", prompt)
                else:
                    log.debug("readline: %s%r", prompt, result)
                return result
            elif c == KEY_BACKSPACE or cb == bytes([127]) or cb == bytes([8]):
                if insptr > 0:
                    await self._readline_echo(self.CODES["CSRLEFT"] + self.CODES["DEL"], echo)
                    insptr -= 1
                    del line[insptr]
                else:
                    await self._readline_echo(BELL, echo)
                continue
            elif c == KEY_DC:
                if insptr < len(line):
                    await self._readline_echo(self.CODES["DEL"], echo)
                    del line[insptr]
                else:
                    await self._readline_echo(BELL, echo)
                continue
            else:
                if len(line) >= self.MAX_LINE:
                    continue  # drop silently: no echo, no growth
                if c < 32:
                    cb = unctrl(c).encode()
                if len(line) > insptr:
                    await self._readline_insert(cb, echo, insptr, line)
                else:
                    await self._readline_echo(cb, echo)
            line[insptr:insptr] = cb
            insptr += len(cb)
            if self._readline_do_echo(echo):
                self._current_line = bytes(line)

    async def getc(self):
        """Return one character from the input queue; raise EOFError once the peer is gone."""
        if self.eof and self.cookedq.empty():
            raise EOFError
        c = await self.cookedq.get()
        if c is None:  # sentinel from the input cooker: connection closed
            self.eof = True
            raise EOFError
        return c

    # --------------------------- Output Functions -----------------------------

    async def write(self, data_bytes):
        """Send a packet. This function cooks output and waits for the socket."""
        data_bytes = data_bytes.replace(IAC, IAC + IAC)
        data_bytes = data_bytes.replace(bytes([10]), bytes([13]) + bytes([10]))
        await self.writecooked(data_bytes)

    async def writecooked(self, data_bytes):
        """Write directly (bypass output cooker) and drain, so a dead peer raises."""
        self.writer.write(data_bytes)
        await self.writer.drain()

    async def writeline(self, data_bytes):
        """Send a packet with line ending."""
        log.debug("writing line %r", data_bytes)
        await self.write(data_bytes + bytes([10]))

    # ------------------------------- Input Cooker -----------------------------
    async def _inputcooker_getc(self):
        """Get one character from the raw queue.
        Raise EOFError on end of stream. SHOULD ONLY BE CALLED FROM THE
        INPUT COOKER."""
        if self.rawq:
            ret = self.rawq[0]
            self.rawq = self.rawq[1:]
            return bytes([ret])
        try:
            ret = await self.reader.read(256)
        except (ConnectionError, OSError):
            ret = b""

        self.eof = not ret
        self.rawq = self.rawq + ret
        if self.eof:
            raise EOFError
        return await self._inputcooker_getc()

    def _inputcooker_ungetc(self, char):
        """Put characters back onto the head of the rawq. SHOULD ONLY
        BE CALLED FROM THE INPUT COOKER."""
        self.rawq = char + self.rawq

    async def _inputcooker_store(self, char):
        """Put the cooked data in the correct queue"""
        if self.sb:
            if len(self.sbdataq) < 256:
                self.sbdataq = self.sbdataq + char
        else:
            await self.inputcooker_store_queue(char)

    async def inputcooker_store_queue(self, char):
        """Put the cooked data in the input queue; blocks (backpressure) when full."""
        if isinstance(char, list | tuple | str | bytes):
            for v in char:
                await self.cookedq.put(v)
        else:
            await self.cookedq.put(char)

    async def inputcooker(self):
        """Input Cooker - Transfer from raw queue to cooked queue.

        Set self.eof when connection is closed.
        """
        try:
            while True:
                cb = await self._inputcooker_getc()
                if not self.iacseq:
                    if cb == IAC:
                        self.iacseq += cb
                        continue
                    elif cb == bytes([13]) and not self.sb:
                        c2b = await self._inputcooker_getc()
                        if c2b == theNULL or c2b == b"":
                            cb = bytes([10])
                        elif c2b == bytes([10]):
                            cb = c2b
                        else:
                            self._inputcooker_ungetc(c2b)
                            cb = bytes([10])
                    await self._inputcooker_store(cb)
                elif len(self.iacseq) == 1:
                    # IAC: IAC CMD [OPTION only for WILL/WONT/DO/DONT]
                    if cb in (DO, DONT, WILL, WONT):
                        self.iacseq += cb
                        continue
                    self.iacseq = b""
                    if cb == IAC:
                        await self._inputcooker_store(cb)
                    else:
                        if cb == SB:  # SB ... SE start.
                            self.sb = 1
                            self.sbdataq = b""
                        elif cb == SE:  # SB ... SE end.
                            self.sb = 0
                        # Callback is supposed to look into the sbdataq
                elif len(self.iacseq) == 2:
                    self.iacseq = b""
        except EOFError:
            pass
        finally:
            # wake up a readline() waiting on the queue so the session can end
            self.eof = True
            try:
                self.cookedq.put_nowait(None)
            except asyncio.QueueFull:
                pass

    async def authentication_ok(self):
        """Checks the authentication and sets the username of the currently connected terminal. Returns True or False"""
        raise NotImplementedError("Please Implement the authentication_ok method")

    # ----------------------- Command Line Processor Engine --------------------

    async def handle(self):
        """The actual service to which the user has connected."""
        try:
            await self.authentication_ok()
        finally:
            if self.inputcooker_task is not None:
                self.inputcooker_task.cancel()
                try:
                    await self.inputcooker_task
                except asyncio.CancelledError:
                    pass


def convert_to_bytes(c):
    if isinstance(c, int):
        if c < 256:
            cb = bytes([c])
        else:
            cb = None
    elif isinstance(c, str):
        cb = bytes(c, "utf-8")
    else:
        cb = c
    return cb
