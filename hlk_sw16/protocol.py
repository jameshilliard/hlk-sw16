"""HLK-SW16 Protocol Support."""
import asyncio
from collections import deque
import logging
import binascii


class SW16Protocol(asyncio.Protocol):
    """HLK-SW16 relay control protocol."""

    transport = None  # type: asyncio.Transport

    def __init__(self, disconnect_callback=None, event_callback=None,
                 loop=None, logger=None):
        """Initialize the HLK-SW16 protocol."""
        if loop:
            self.loop = loop
        else:
            self.loop = asyncio.get_event_loop()
        if logger:
            self.logger = logger
        else:
            self.logger = logging.getLogger(__name__)
        self._buffer = b''
        self.disconnect_callback = disconnect_callback
        self.event_callback = event_callback
        self._waiters = deque()
        self._status_waiters = deque()
        self._in_transaction = False
        self._active_transaction = None
        self.states = {}

    def connection_made(self, transport):
        """Initialize protocol transport."""
        self.transport = transport
        self.logger.debug('connected')

    def data_received(self, data):
        """Add incoming data to buffer."""
        self.logger.debug('received data: %s', binascii.hexlify(data))
        self.logger.debug(data)
        self.logger.debug('received buffer: %s',
                          binascii.hexlify(self._buffer))
        self._buffer += data
        self._handle_lines()

    def _handle_lines(self):
        """Assemble incoming data into per-line packets."""
        while b'\xdd' in self._buffer:
            linebuf, self._buffer = self._buffer.rsplit(b'\xdd', 1)
            line = linebuf[-19:]
            self._buffer += linebuf[:-19]
            self.logger.debug('received line: %s', binascii.hexlify(line))
            if self._valid_packet(line):
                self.logger.debug('received valid line: %s',
                                  binascii.hexlify(line))
                self._handle_raw_packet(line)
            else:
                self.logger.warning('dropping invalid data: %s',
                                    binascii.hexlify(line))

    @staticmethod
    def _valid_packet(raw_packet):
        """Validate incoming packet."""
        if raw_packet[0:1] != b'\xcc':
            return False
        if len(raw_packet) != 19:
            return False
        checksum = 0
        for i in range(1, 17):
            checksum += raw_packet[i]
        if checksum != raw_packet[18]:
            return False
        return True

    def _handle_raw_packet(self, raw_packet):
        """Parse incoming packet."""
        if raw_packet[1:2] == b'\x1f':
            year = raw_packet[2]
            month = raw_packet[3]
            day = raw_packet[4]
            hour = raw_packet[5]
            minute = raw_packet[6]
            sec = raw_packet[7]
            week = raw_packet[8]
            self.logger.debug(
                'received date: Year: %s, Month: %s, Day: %s, Hour: %s, '
                'Minute: %s, Sec: %s, Week %s',
                year, month, day, hour, minute, sec, week)
        elif raw_packet[1:2] == b'\x0c':
            states = {}
            for switch in range(0, 16):
                if raw_packet[2+switch:3+switch] == b'\x02':
                    states[format(switch, 'x')] = True
                    self.states[format(switch, 'x')] = True
                elif raw_packet[2+switch:3+switch] == b'\x01':
                    states[format(switch, 'x')] = False
                    self.states[format(switch, 'x')] = False
            self.logger.debug(states)
            if self.event_callback:
                self.event_callback(states)
            if self._in_transaction:
                self._in_transaction = False
                self._active_transaction.set_result(states)
                while self._status_waiters:
                    waiter = self._status_waiters.popleft()
                    waiter.set_result(states)
                if self._waiters:
                    self._send_packet()
        else:
            pass

    def _send_packet(self):
        """Write next packet in send queue."""
        waiter, packet = self._waiters.popleft()
        self._active_transaction = waiter
        self._in_transaction = True
        self.transport.write(packet)

    def send(self, packet):
        """Add packet to send queue."""
        fut = self.loop.create_future()
        self._waiters.append((fut, packet))
        if self._waiters and self._in_transaction is False:
            self._send_packet()
        return fut

    @staticmethod
    def _format_packet(command):
        """Format packet to be sent."""
        frame_header = b"\xaa"
        verify = b"\x0b"
        send_delim = b"\xbb"
        return frame_header + command.ljust(17, b"\x00") + verify + send_delim

    async def turn_on(self, switch=None):
        """Turn on relay."""
        if switch is not None:
            packet = self._format_packet(b"\x10" + switch + b"\x02")
        else:
            packet = self._format_packet(b"\x0b")
        self.logger.debug(packet)
        states = await self.send(packet)
        return states

    async def turn_off(self, switch=None):
        """Turn off relay."""
        if switch is not None:
            packet = self._format_packet(b"\x10" + switch + b"\x01")
        else:
            packet = self._format_packet(b"\x0a")
        self.logger.debug(packet)
        states = await self.send(packet)
        return states

    async def status(self):
        """Get current relay status."""
        if self._waiters or self._in_transaction:
            fut = self.loop.create_future()
            self._status_waiters.append(fut)
            states = await fut
        else:
            packet = self._format_packet(b"\x1e")
            self.logger.debug(packet)
            states = await self.send(packet)
        return states

    def connection_lost(self, exc):
        """Log when connection is closed, if needed call callback."""
        if exc:
            self.logger.exception('disconnected due to exception')
        else:
            self.logger.info('disconnected because of close/abort.')
        if self.disconnect_callback:
            self.disconnect_callback(exc)


async def create_hlk_sw16_connection(port=None, host=None, event_callback=None,
                                     disconnect_callback=None, loop=None,
                                     logger=None):
    """Create HLK-SW16 manager class, returns transport coroutine."""
    # use default protocol if not specified
    conn = await loop.create_connection(
        lambda: SW16Protocol(disconnect_callback=disconnect_callback,
                             event_callback=event_callback,
                             loop=loop, logger=logger),
        host=host,
        port=port)

    return conn
