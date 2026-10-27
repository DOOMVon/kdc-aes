import argparse
import threading

from cipher import encrypt
from console import show
from net import Channel, listen
from peer import Peer, SecureSession
from protocol import ProtocolError, new_nonce, read_nonce, split, transform, unseal, validate_identity, validate_session_key


class Bob(Peer):
    def __init__(self, args):
        super().__init__(args.id)
        self.server = listen(args.host, args.port)
        print(f"{self.user_id} listening on {args.host}:{args.port}")
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while self.running:
            try:
                sock, _ = self.server.accept()
            except OSError:
                break
            channel = Channel(sock)
            print(f"\nKoneksi masuk dari {channel.peer}")
            try:
                session = self.authenticate(channel)
            except (OSError, ValueError) as error:
                print(f"\nAutentikasi gagal: {error}")
                channel.reject(str(error))
                continue
            self.session = session
            self.announce(session)
            session.listen()

    def authenticate(self, channel):
        ticket = channel.expect("step3")
        try:
            session_key, alice_id = split(unseal(ticket, self.master_key, "Ticket"), 2)
            validate_session_key(session_key)
            validate_identity(alice_id)
        except ValueError as error:
            raise ProtocolError(str(error)) from None
        show(f"STEP 3  {channel.peer} -> {self.user_id}", {
            "E(Kb, Ks || IDA)": ticket,
            "Dekripsi dengan Kb": f"Ks = {session_key}, IDA = {alice_id}",
        })
        nonce = new_nonce()
        challenge = encrypt(str(nonce), session_key)
        channel.send({"type": "step4", "data": challenge})
        show(f"STEP 4  {self.user_id} -> {alice_id}", {"N2": nonce, "E(Ks, N2)": challenge})
        response = channel.expect("step5")
        answer = read_nonce(unseal(response, session_key, "f(N2)"))
        if answer != transform(nonce):
            raise ProtocolError("f(N2) tidak sesuai, peer tidak memegang Ks yang sama")
        show(f"STEP 5  {alice_id} -> {self.user_id}", {"E(Ks, f(N2))": response, "f(N2) valid": answer})
        return SecureSession(channel, session_key, self.user_id, alice_id)

    def stop(self, _=""):
        super().stop()
        self.server.close()


def main():
    parser = argparse.ArgumentParser(description="Bob: responder key distribution")
    parser.add_argument("--id", default="bob", type=validate_identity)
    parser.add_argument("--host", default="0.0.0.0", help="IP yang di-bind Bob")
    parser.add_argument("--port", type=int, default=6000)
    args = parser.parse_args()
    print("=== BOB ===")
    Bob(args).run()


if __name__ == "__main__":
    main()
