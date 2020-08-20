"""HLK-SW16 Protocol Support."""
import asyncio
from collections import deque
import logging
import codecs
import binascii


class SW16Protocol(asyncio.Protocol):
    """HLK-SW16 relay control protocol."""

    transport = None  # type: asyncio.Transport

    def __init__(self, client, disconnect_callback=None, loop=None,
                 logger=None):
        """Initialize the HLK-SW16 protocol."""
        self.client = client
        self.loop = loop
        self.logger = logger
        self._buffer = b''
        self.disconnect_callback = disconnect_callback
        self._timeout = None
        self._cmd_timeout = None
        self._keep_alive = None

    def connection_made(self, transport):
        """Initialize protocol transport."""
        self.transport = transport
        self._reset_timeout()

    def _send_keepalive_packet(self):
        """Send a keep alive packet."""
        if not self.client.in_transaction:
            packet = self.format_packet(b"\x12")
            self.logger.debug('sending keep alive packet')
            self.transport.write(packet)

    def _reset_timeout(self):
        """Reset timeout for date keep alive."""
        if self._timeout:
            self._timeout.cancel()
        self._timeout = self.loop.call_later(self.client.timeout,
                                             self.transport.close)
        if self._keep_alive:
            self._keep_alive.cancel()
        self._keep_alive = self.loop.call_later(
            self.client.keep_alive_interval,
            self._send_keepalive_packet)

    def reset_cmd_timeout(self):
        """Reset timeout for command execution."""
        if self._cmd_timeout:
            self._cmd_timeout.cancel()
        self._cmd_timeout = self.loop.call_later(self.client.timeout,
                                                 self.transport.close)

    def data_received(self, data):
        """Add incoming data to buffer."""
        self._buffer += data
        self._handle_lines()

    def _handle_lines(self):
        """Assemble incoming data into per-line packets."""
        while b'\xdd' in self._buffer:
            linebuf, self._buffer = self._buffer.rsplit(b'\xdd', 1)
            line = linebuf[-19:]
            self._buffer += linebuf[:-19]
            if self._valid_packet(line):
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
        if (checksum % 256) != raw_packet[18]:
            return False
        return True

    def _handle_raw_packet(self, raw_packet):
        """Parse incoming packet."""
        if raw_packet[1:2] == b'\x1f':
            self._reset_timeout()
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
        elif raw_packet[1:2] == b'\x0e':
            self._reset_timeout()
            sec = raw_packet[2]
            minute = raw_packet[3]
            hour = raw_packet[4]
            day = raw_packet[5]
            month = raw_packet[6]
            week = raw_packet[7]
            year = raw_packet[8]
            self.logger.debug(
                'received date: Year: %s, Month: %s, Day: %s, Hour: %s, '
                'Minute: %s, Sec: %s, Week %s',
                year, month, day, hour, minute, sec, week)
        elif raw_packet[1:2] == b'\x0c':
            self._reset_timeout()
            states = {}
            changes = []
            for switch in range(0, 16):
                if raw_packet[2+switch:3+switch] == b'\x01':
                    states[format(switch, 'x')] = True
                    if (self.client.states.get(format(switch, 'x'), None)
                            is not True):
                        changes.append(format(switch, 'x'))
                        self.client.states[format(switch, 'x')] = True
                elif raw_packet[2+switch:3+switch] == b'\x02':
                    states[format(switch, 'x')] = False
                    if (self.client.states.get(format(switch, 'x'), None)
                            is not False):
                        changes.append(format(switch, 'x'))
                        self.client.states[format(switch, 'x')] = False
            for switch in changes:
                for status_cb in self.client.status_callbacks.get(switch, []):
                    status_cb(states[switch])
            self.logger.debug(states)
            if self.client.in_transaction:
                self.client.in_transaction = False
                self.client.active_packet = False
                self.client.active_transaction.set_result(states)
                while self.client.status_waiters:
                    waiter = self.client.status_waiters.popleft()
                    waiter.set_result(states)
                if self.client.waiters:
                    self.send_packet()
                else:
                    self._cmd_timeout.cancel()
            elif self._cmd_timeout:
                self._cmd_timeout.cancel()
        else:
            self.logger.warning('received unknown packet: %s',
                                binascii.hexlify(raw_packet))

    def send_packet(self):
        """Write next packet in send queue."""
        waiter, packet = self.client.waiters.popleft()
        self.logger.debug('sending packet: %s', binascii.hexlify(packet))
        self.client.active_transaction = waiter
        self.client.in_transaction = True
        self.client.active_packet = packet
        self.reset_cmd_timeout()
        self.transport.write(packet)

    @staticmethod
    def format_packet(command):
        """Format packet to be sent."""
        frame_header = b"\xaa"
        verify = b"\x0b"
        send_delim = b"\xbb"
        return frame_header + command.ljust(17, b"\x00") + verify + send_delim

    def connection_lost(self, exc):
        """Log when connection is closed, if needed call callback."""
        if exc:
            self.logger.error('disconnected due to error')
        else:
            self.logger.info('disconnected because of close/abort.')
        if self._keep_alive:
            self._keep_alive.cancel()
        if self.disconnect_callback:
            asyncio.ensure_future(self.disconnect_callback(), loop=self.loop)


class SW16Client:
    """HLK-SW16 client wrapper class."""

    def __init__(self, host, port=8080,
                 disconnect_callback=None, reconnect_callback=None,
                 loop=None, logger=None, timeout=10, reconnect_interval=10,
                 keep_alive_interval=3):
        """Initialize the HLK-SW16 client wrapper."""
        if loop:
            self.loop = loop
        else:
            self.loop = asyncio.get_event_loop()
        if logger:
            self.logger = logger
        else:
            self.logger = logging.getLogger(__name__)
        self.host = host
        self.port = port
        self.transport = None
        self.protocol = None
        self.is_connected = False
        self.reconnect = True
        self.timeout = timeout
        self.reconnect_interval = reconnect_interval
        self.keep_alive_interval = keep_alive_interval
        self.disconnect_callback = disconnect_callback
        self.reconnect_callback = reconnect_callback
        self.waiters = deque()
        self.status_waiters = deque()
        self.in_transaction = False
        self.active_transaction = None
        self.active_packet = None
        self.status_callbacks = {}
        self.states = {}

    async def setup(self):
        """Set up the connection with automatic retry."""
        while True:
            fut = self.loop.create_connection(
                lambda: SW16Protocol(
                    self,
                    disconnect_callback=self.handle_disconnect_callback,
                    loop=self.loop, logger=self.logger),
                host=self.host,
                port=self.port)
            try:
                self.transport, self.protocol = \
                    await asyncio.wait_for(fut, timeout=self.timeout)
            except asyncio.TimeoutError:
                self.logger.warning("Could not connect due to timeout error.")
            except OSError as exc:
                self.logger.warning("Could not connect due to error: %s",
                                    str(exc))
            else:
                self.is_connected = True
                if self.reconnect_callback:
                    self.reconnect_callback()
                break
            await asyncio.sleep(self.reconnect_interval)

    def stop(self):
        """Shut down transport."""
        self.reconnect = False
        self.logger.debug("Shutting down.")
        if self.transport:
            self.transport.close()

    async def handle_disconnect_callback(self):
        """Reconnect automatically unless stopping."""
        self.is_connected = False
        if self.disconnect_callback:
            self.disconnect_callback()
        if self.reconnect:
            self.logger.debug("Protocol disconnected...reconnecting")
            await self.setup()
            self.protocol.reset_cmd_timeout()
            if self.in_transaction:
                self.protocol.transport.write(self.active_packet)
            else:
                packet = self.protocol.format_packet(b"\x1e")
                self.protocol.transport.write(packet)

    def register_status_callback(self, callback, switch):
        """Register a callback which will fire when state changes."""
        if self.status_callbacks.get(switch, None) is None:
            self.status_callbacks[switch] = []
        self.status_callbacks[switch].append(callback)

    def _send(self, packet):
        """Add packet to send queue."""
        fut = self.loop.create_future()
        self.waiters.append((fut, packet))
        if self.waiters and self.in_transaction is False:
            self.protocol.send_packet()
        return fut

    async def turn_on(self, switch=None):
        """Turn on relay."""
        if switch is not None:
            switch = codecs.decode(switch.rjust(2, '0'), 'hex')
            packet = self.protocol.format_packet(b"\x10" + switch + b"\x01")
        else:
            packet = self.protocol.format_packet(b"\x0a")
        states = await self._send(packet)
        return states

    async def turn_off(self, switch=None):
        """Turn off relay."""
        if switch is not None:
            switch = codecs.decode(switch.rjust(2, '0'), 'hex')
            packet = self.protocol.format_packet(b"\x10" + switch + b"\x02")
        else:
            packet = self.protocol.format_packet(b"\x0b")
        states = await self._send(packet)
        return states

    async def status(self, switch=None):
        """Get current relay status."""
        if switch is not None:
            if self.waiters or self.in_transaction:
                fut = self.loop.create_future()
                self.status_waiters.append(fut)
                states = await fut
                state = states[switch]
            else:
                packet = self.protocol.format_packet(b"\x1e")
                states = await self._send(packet)
                state = states[switch]
        else:
            if self.waiters or self.in_transaction:
                fut = self.loop.create_future()
                self.status_waiters.append(fut)
                state = await fut
            else:
                packet = self.protocol.format_packet(b"\x1e")
                state = await self._send(packet)
        return state


async def create_hlk_sw16_connection(port=None, host=None,
                                     disconnect_callback=None,
                                     reconnect_callback=None, loop=None,
                                     logger=None, timeout=None,
                                     reconnect_interval=None,
                                     keep_alive_interval=None):
    """Create HLK-SW16 Client class."""
    client = SW16Client(host, port=port,
                        disconnect_callback=disconnect_callback,
                        reconnect_callback=reconnect_callback,
                        loop=loop, logger=logger,
                        timeout=timeout, reconnect_interval=reconnect_interval,
                        keep_alive_interval=keep_alive_interval)
    await client.setup()

    return client
