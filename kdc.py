import argparse
import threading

from cipher import encrypt, validate_key
from console import show, show_commands
from net import Channel, listen
from protocol import ProtocolError, join, new_session_key, split, validate_identity, validate_session_key


class KeyDistributionCenter:
    def __init__(self):
        self.master_keys = {}
        self.fixed_session_key = None
        self.lock = threading.Lock()

    def register(self, user_id, key):
        with self.lock:
            self.master_keys[validate_identity(user_id)] = validate_key(key)

    def remove(self, user_id):
        with self.lock:
            return self.master_keys.pop(user_id, None) is not None

    def issue(self, request):
        id_a, id_b, nonce = split(request, 3)
        with self.lock:
            missing = [user for user in (id_a, id_b) if user not in self.master_keys]
            if missing:
                raise ProtocolError(f"ID belum terdaftar di KDC: {', '.join(missing)}")
            key_a, key_b = self.master_keys[id_a], self.master_keys[id_b]
            session_key = self.fixed_session_key or new_session_key()
        ticket = encrypt(join(session_key, id_a), key_b)
        response = encrypt(join(session_key, id_a, id_b, nonce, ticket), key_a)
        return session_key, ticket, response


class KdcNode:
    def __init__(self, host, port):
        self.kdc = KeyDistributionCenter()
        self.server = listen(host, port)
        self.running = True
        self.commands = {
            "/set": (self.set_key, "daftarkan atau ganti master key: /set <id> <key>"),
            "/del": (self.delete_key, "hapus master key: /del <id>"),
            "/list": (self.list_keys, "tampilkan master key yang terdaftar"),
            "/session": (self.set_session_key, "session key berikutnya: /session auto | /session <key>"),
            "/help": (self.show_help, "tampilkan daftar perintah"),
            "/exit": (self.stop, "matikan KDC"),
        }
        print(f"KDC listening on {host}:{port}")

    def serve(self):
        while self.running:
            try:
                sock, _ = self.server.accept()
            except OSError:
                break
            threading.Thread(target=self.handle, args=(Channel(sock),), daemon=True).start()

    def handle(self, channel):
        with channel:
            try:
                request = channel.expect("step1")
                show(f"STEP 1  {channel.peer} -> KDC", {"IDA || IDB || N1": request})
                session_key, ticket, response = self.kdc.issue(request)
                channel.send({"type": "step2", "data": response})
                show(f"STEP 2  KDC -> {channel.peer}", {
                    "Ks": session_key,
                    "Ticket E(Kb, Ks || IDA)": ticket,
                    "E(Ka, Ks||IDA||IDB||N1||Ticket)": response,
                })
            except (OSError, ValueError) as error:
                print(f"\n[KDC] Request dari {channel.peer} ditolak: {error}")
                channel.reject(str(error))

    def run(self):
        threading.Thread(target=self.serve, daemon=True).start()
        self.show_help()
        while self.running:
            try:
                line = input()
            except (EOFError, KeyboardInterrupt):
                line = "/exit"
            command, _, argument = line.strip().partition(" ")
            if command in self.commands:
                self.commands[command][0](argument)
            elif command:
                print("Perintah tidak dikenal, ketik /help")

    def set_key(self, argument):
        user_id, _, key = argument.partition(" ")
        try:
            self.kdc.register(user_id, key)
        except ValueError as error:
            print(f"Gagal: {error}")
            return
        print(f"Master key {user_id} disimpan.")

    def delete_key(self, argument):
        removed = self.kdc.remove(argument.strip())
        print(f"Master key {argument.strip()} dihapus." if removed else "ID tidak ditemukan.")

    def list_keys(self, _):
        if not self.kdc.master_keys:
            print("Belum ada master key terdaftar.")
            return
        show("MASTER KEYS", dict(self.kdc.master_keys))

    def set_session_key(self, argument):
        if argument.strip().lower() in ("", "auto"):
            self.kdc.fixed_session_key = None
            print("Session key dibangkitkan acak (16 karakter) untuk setiap request.")
            return
        try:
            self.kdc.fixed_session_key = validate_session_key(argument)
        except ValueError as error:
            print(f"Gagal: {error}")
            return
        print(f"Request berikutnya memakai session key tetap: {argument}")

    def show_help(self, _=""):
        show_commands(self.commands)

    def stop(self, _=""):
        self.running = False
        self.server.close()


def main():
    parser = argparse.ArgumentParser(description="Key Distribution Center")
    parser.add_argument("--host", default="0.0.0.0", help="IP yang di-bind KDC")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    print("=== KDC ===")
    KdcNode(args.host, args.port).run()


if __name__ == "__main__":
    main()
