import threading

from cipher import MODES, cipher_name, decrypt, encrypt
from console import read_key, show, show_commands
from net import ConnectionClosed


class SecureSession:
    def __init__(self, channel, session_key, local_id, peer_id):
        self.channel = channel
        self.session_key = session_key
        self.local_id = local_id
        self.peer_id = peer_id
        self.closed = threading.Event()

    @property
    def active(self):
        return not self.closed.is_set()

    def send(self, plaintext, mode):
        ciphertext = encrypt(plaintext, self.session_key, mode)
        self.channel.send({"type": "chat", "mode": mode, "data": ciphertext})
        show(f"SEND {self.local_id} -> {self.peer_id} | {cipher_name(self.session_key, mode)}", {
            "Plaintext": plaintext,
            "Ciphertext": ciphertext,
        })

    def listen(self):
        try:
            while True:
                message = self.channel.receive()
                if message.get("type") == "bye":
                    print(f"\n{self.peer_id} menutup sesi.")
                    break
                if message.get("type") == "error":
                    print(f"\n[ERROR] {self.peer_id}: {message.get('data')}")
                    break
                self.show_incoming(message)
        except (ConnectionClosed, ValueError) as error:
            if self.active:
                print(f"\n{error}")
        finally:
            self.closed.set()
            self.channel.close()

    def show_incoming(self, message):
        mode = message.get("mode", "CBC")
        ciphertext = str(message.get("data"))
        fields = {"Ciphertext": ciphertext}
        try:
            fields["Plaintext"] = decrypt(ciphertext, self.session_key, mode)
        except ValueError as error:
            fields["Gagal"] = str(error)
        show(f"RECV {self.peer_id} -> {self.local_id} | {cipher_name(self.session_key, mode)}", fields)

    def close(self):
        if not self.active:
            return
        self.closed.set()
        try:
            self.channel.send({"type": "bye"})
        except OSError:
            pass
        self.channel.close()


class Peer:
    def __init__(self, user_id):
        self.user_id = user_id
        self.master_key = read_key(f"Master key {user_id} (sama dengan yang terdaftar di KDC): ")
        self.mode = "CBC"
        self.session = None
        self.running = True
        self.commands = {
            "/status": (self.show_status, "tampilkan key, mode, dan sesi saat ini"),
            "/mode": (self.set_mode, "ganti mode AES untuk pesan berikutnya: /mode cbc | /mode ecb"),
            "/key": (self.change_master_key, "ganti master key tanpa restart program"),
            "/help": (self.show_help, "tampilkan daftar perintah"),
            "/exit": (self.stop, "tutup sesi dan keluar"),
        }

    @property
    def active_session(self):
        return self.session if self.session and self.session.active else None

    def run(self):
        self.show_help()
        while self.running:
            try:
                line = input()
            except (EOFError, KeyboardInterrupt):
                line = "/exit"
            self.dispatch(line)

    def dispatch(self, line):
        if not line.strip():
            return
        command, _, argument = line.strip().partition(" ")
        if command in self.commands:
            self.commands[command][0](argument.strip())
        elif command.startswith("/"):
            print("Perintah tidak dikenal, ketik /help")
        else:
            self.send(line)

    def send(self, plaintext):
        session = self.active_session
        if session is None:
            print("Belum ada sesi aman dengan peer.")
            return
        try:
            session.send(plaintext, self.mode)
        except ValueError as error:
            print(f"Pesan tidak dikirim: {error}")
        except OSError:
            print(f"Koneksi dengan {session.peer_id} terputus.")

    def announce(self, session):
        print(f"\nSesi aman dengan {session.peer_id} terbentuk. Session key Ks = {session.session_key}")
        print(f"Komunikasi selanjutnya memakai {cipher_name(session.session_key, self.mode)}. Ketik pesan lalu Enter.")

    def show_status(self, _):
        session = self.active_session
        show("STATUS", {
            "ID": self.user_id,
            "Master key": self.master_key,
            "Mode": self.mode,
            "Peer": session.peer_id if session else "-",
            "Session key": session.session_key if session else "-",
            "Cipher": cipher_name(session.session_key, self.mode) if session else "-",
        })

    def set_mode(self, argument):
        mode = argument.upper()
        if mode not in MODES:
            print("Gunakan /mode cbc atau /mode ecb")
            return
        self.mode = mode
        print(f"Mode pesan sekarang {mode}.")

    def change_master_key(self, _):
        self.master_key = read_key("Master key baru: ")
        print("Master key diganti. Berlaku pada distribusi key berikutnya.")

    def show_help(self, _=""):
        show_commands(self.commands)

    def stop(self, _=""):
        if self.active_session:
            self.session.close()
        self.running = False
