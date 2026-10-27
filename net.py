import argparse
import json
import socket

from protocol import ProtocolError


class ConnectionClosed(ConnectionError):
    pass


def parse_address(text):
    host, _, port = text.rpartition(":")
    if not host or not port.isdigit():
        raise argparse.ArgumentTypeError("Format alamat harus IP:PORT, contoh 192.168.1.20:5000")
    return host, int(port)


def listen(host, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen()
    return server


class Channel:
    def __init__(self, sock):
        self.sock = sock
        self.reader = sock.makefile("r", encoding="utf-8", newline="\n")
        self.local = "{}:{}".format(*sock.getsockname())
        self.peer = "{}:{}".format(*sock.getpeername())

    @classmethod
    def connect(cls, address, bind_ip=None):
        source = (bind_ip, 0) if bind_ip else None
        sock = socket.create_connection(address, timeout=5, source_address=source)
        sock.settimeout(None)
        return cls(sock)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def send(self, message):
        self.sock.sendall((json.dumps(message) + "\n").encode("utf-8"))

    def receive(self):
        try:
            line = self.reader.readline()
        except (OSError, ValueError):
            line = ""
        if not line:
            raise ConnectionClosed(f"Koneksi dengan {self.peer} terputus")
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            raise ProtocolError("Frame yang diterima bukan JSON yang valid") from None
        if not isinstance(message, dict):
            raise ProtocolError("Frame yang diterima tidak memiliki format yang benar")
        return message

    def expect(self, message_type):
        message = self.receive()
        if message.get("type") == "error":
            raise ProtocolError(f"Ditolak oleh {self.peer}: {message.get('data')}")
        if message.get("type") != message_type or not isinstance(message.get("data"), str):
            raise ProtocolError(f"Diharapkan {message_type}, diterima {message.get('type')}")
        return message["data"]

    def reject(self, reason):
        try:
            self.send({"type": "error", "data": reason})
        except OSError:
            pass
        self.close()

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
        self.reader.close()
