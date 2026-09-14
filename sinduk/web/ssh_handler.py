"""SSH connection handler for web-based terminal access."""

import re
import os
import paramiko  # type: ignore[import-untyped]
import threading
import queue
import time
import socket
from typing import Optional
from ..log import get_logger

logger = get_logger("sinduk.web.ssh_handler")


class SSHTerminal:
    """Manages SSH connection and terminal I/O."""

    def __init__(
        self,
        hostname: str,
        username: str,
        port: int = 22,
        password: Optional[str] = None,
        key_filename: Optional[str] = None,
    ):
        self.hostname = hostname
        self.username = username
        self.port = port
        self.password = password
        self.key_filename = key_filename

        self.client: Optional[paramiko.SSHClient] = None
        self.channel = None
        self.output_queue: queue.Queue[str] = queue.Queue()
        self.connected = False
        self.reader_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def _strip_ansi(self, text: str) -> str:
        """Remove ANSI/VT100 escape sequences and bare CRs from *text*."""
        _ANSI_ESCAPE = re.compile(
            r"\x1B(?:"
            r"\[[0-?]*[ -/]*[@-~]"  # CSI sequences
            r"|[\]PX^_].*?(?:\x1B\\|\x07)"  # OSC, DCS, SOS, PM, APC
            r"|[\(\)][AB012]"  # charset designation
            r"|."  # fallback (any ESC sequence)
            r")|\r",  # remove carriage return
            re.DOTALL,
        )
        return _ANSI_ESCAPE.sub("", text)

    def connect(self) -> bool:
        """Establish SSH connection."""
        try:
            self.client = paramiko.SSHClient()
            self.client.load_system_host_keys()
            try:
                self.client.load_host_keys(os.path.expanduser("~/.ssh/known_hosts"))
            except OSError:
                pass
            self.client.set_missing_host_key_policy(paramiko.RejectPolicy())

            connect_kwargs = {
                "hostname": self.hostname,
                "port": self.port,
                "username": self.username,
                "timeout": 10,
                "banner_timeout": 10,
                "auth_timeout": 10,
                "look_for_keys": True,
                "allow_agent": True,
            }

            if self.key_filename:
                connect_kwargs["key_filename"] = self.key_filename

            if self.password:
                connect_kwargs["password"] = self.password

            self.client.connect(**connect_kwargs)

            transport = self.client.get_transport()
            if transport:
                transport.set_keepalive(30)

            self.channel = self.client.invoke_shell(
                term="xterm",
                width=200,
                height=50,
            )
            # self.channel.setblocking(False)

            self.connected = True
            self._stop_event.clear()

            self.reader_thread = threading.Thread(
                target=self._read_output,
                daemon=True,
            )
            self.reader_thread.start()

            logger.info(
                "Connected to %s@%s:%s",
                self.username,
                self.hostname,
                self.port,
            )
            return True

        except (paramiko.SSHException, socket.error) as exc:
            logger.error("SSH connection failed: %s", exc)
            self.connected = False
            return False

    def _read_channel_data(self, recv_method) -> bool:
        if self.channel is None:
            return False
        if recv_method():
            data = recv_method(recv_buffer=4096) if hasattr(recv_method, "__call__") else None
            if data:
                self._queue_output(data)
                return True
        return False

    def _read_output(self) -> None:
        """Background reader thread."""
        while not self._stop_event.is_set() and self.connected:
            try:
                if self.channel is None:
                    break

                self._read_and_queue(self.channel.recv_ready, self.channel.recv)
                self._read_and_queue(self.channel.recv_stderr_ready, self.channel.recv_stderr)

                time.sleep(0.02)

            except socket.timeout:
                continue
            except Exception as exc:  # noqa: BLE001
                logger.error("SSH read error: %s", exc)
                break

    def _read_and_queue(self, ready_method, recv_method):
        if ready_method():
            data = recv_method(4096)
            if data:
                self._queue_output(data)

    def _queue_output(self, data: bytes) -> None:
        text = data.decode("utf-8", errors="replace")
        clean = self._strip_ansi(text)
        if clean:
            self.output_queue.put(clean)

    def send_command(self, command: str) -> bool:
        if not self.connected or not self.channel:
            return False
        try:
            self.channel.send(command)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error("Send command failed: %s", exc)
            return False

    def get_output(self) -> str:
        output = ""
        try:
            while True:
                output += self.output_queue.get_nowait()
        except queue.Empty:
            pass
        return output

    def disconnect(self) -> None:
        self._stop_event.set()

        try:
            if self.channel:
                self.channel.close()
            if self.client:
                self.client.close()

            if self.reader_thread and self.reader_thread.is_alive():
                self.reader_thread.join(timeout=2)

        except Exception as exc:  # noqa: BLE001
            logger.error("Disconnect error: %s", exc)

        finally:
            self.connected = False
            logger.info("Disconnected from %s@%s", self.username, self.hostname)


class SSHConnectionManager:
    """Manages multiple SSH connections."""

    def __init__(self):
        self.connections: dict[str, SSHTerminal] = {}
        self._lock = threading.Lock()

    def create_connection(
        self,
        connection_id: str,
        hostname: str,
        username: str,
        port: int = 22,
        password: Optional[str] = None,
        key_filename: Optional[str] = None,
    ) -> bool:
        try:
            terminal = SSHTerminal(hostname, username, port, password, key_filename)
            if terminal.connect():
                with self._lock:
                    self.connections[connection_id] = terminal
                return True
            return False
        except Exception as exc:  # noqa: BLE001
            logger.error("Create connection failed: %s", exc)
            return False

    def get_connection(self, connection_id: str) -> Optional[SSHTerminal]:
        return self.connections.get(connection_id)

    def close_connection(self, connection_id: str) -> None:
        with self._lock:
            if connection_id in self.connections:
                self.connections[connection_id].disconnect()
                del self.connections[connection_id]
