import argparse
import threading

from cipher import encrypt
from console import show
from net import Channel, parse_address
from peer import Peer, SecureSession
from protocol import ProtocolError, join, new_nonce, read_nonce, split, transform, unseal, validate_identity


class Alice(Peer):
    def __init__(self, args):
        super().__init__(args.id)
        self.bob_id = args.peer_id
        self.kdc_address = args.kdc
        self.bob_address = args.bob
        self.bind_ip = args.bind
        self.commands = {
            "/connect": (self.connect, "jalankan langkah 1-5 (ulangi untuk session key baru)"),
            **self.commands,
        }

    def connect(self, _=""):
        if self.active_session:
            self.session.close()
        try:
            session_key, ticket = self.request_session_key()
            self.session = self.authenticate(session_key, ticket)
        except (OSError, ValueError) as error:
            print(f"\nKey distribution gagal: {error}")
            return
        self.announce(self.session)
        threading.Thread(target=self.session.listen, daemon=True).start()

    def request_session_key(self):
        nonce = new_nonce()
        request = join(self.user_id, self.bob_id, nonce)
        with Channel.connect(self.kdc_address, self.bind_ip) as kdc:
            kdc.send({"type": "step1", "data": request})
            show(f"STEP 1  {self.user_id} ({kdc.local}) -> KDC ({kdc.peer})", {"IDA || IDB || N1": request})
            response = kdc.expect("step2")
        session_key, id_a, id_b, echoed_nonce, ticket = split(unseal(response, self.master_key, "Respons KDC"), 5)
        if (id_a, id_b, echoed_nonce) != (self.user_id, self.bob_id, str(nonce)):
            raise ProtocolError("IDA, IDB, atau N1 pada respons KDC tidak cocok dengan request")
        show(f"STEP 2  KDC -> {self.user_id}", {
            "Ciphertext": response,
            "Dekripsi dengan Ka": "Ks || IDA || IDB || N1 || Ticket",
            "Ks": session_key,
            "N1 cocok": echoed_nonce,
            "Ticket (untuk Bob)": ticket,
        })
        return session_key, ticket

    def authenticate(self, session_key, ticket):
        channel = Channel.connect(self.bob_address, self.bind_ip)
        try:
            channel.send({"type": "step3", "data": ticket})
            show(f"STEP 3  {self.user_id} ({channel.local}) -> {self.bob_id} ({channel.peer})", {
                "E(Kb, Ks || IDA)": ticket,
            })
            challenge = channel.expect("step4")
            nonce = read_nonce(unseal(challenge, session_key, "N2"))
            answer = transform(nonce)
            response = encrypt(str(answer), session_key)
            channel.send({"type": "step5", "data": response})
        except (OSError, ValueError):
            channel.close()
            raise
        show(f"STEP 4  {self.bob_id} -> {self.user_id}", {"E(Ks, N2)": challenge, "N2": nonce})
        show(f"STEP 5  {self.user_id} -> {self.bob_id}", {"f(N2) = N2 + 1": answer, "E(Ks, f(N2))": response})
        return SecureSession(channel, session_key, self.user_id, self.bob_id)


def main():
    parser = argparse.ArgumentParser(description="Alice: initiator key distribution")
    parser.add_argument("--id", default="alice", type=validate_identity)
    parser.add_argument("--peer-id", default="bob", type=validate_identity)
    parser.add_argument("--kdc", required=True, type=parse_address, help="alamat KDC, contoh 192.168.1.20:5000")
    parser.add_argument("--bob", required=True, type=parse_address, help="alamat Bob, contoh 192.168.1.30:6000")
    parser.add_argument("--bind", help="IP lokal Alice jika perangkat punya lebih dari satu IP")
    args = parser.parse_args()
    print("=== ALICE ===")
    Alice(args).run()


if __name__ == "__main__":
    main()
