from aes import AES, INV_S_BOX, S_BOX, expand_key, pad, unpad
from cipher import decrypt, encrypt
from kdc import KeyDistributionCenter
from protocol import ProtocolError, join, split, transform, unseal

passed = 0


def check(name, condition):
    global passed
    assert condition, f"GAGAL: {name}"
    passed += 1
    print(f"[OK] {name}")


def raises(function, *args):
    try:
        function(*args)
    except ValueError:
        return True
    return False


check("S-box hasil GF(2^8) inverse + affine: S[00]=63, S[53]=ED", S_BOX[0x00] == 0x63 and S_BOX[0x53] == 0xED)
check("Inverse S-box membalik S-box", all(INV_S_BOX[S_BOX[x]] == x for x in range(256)))

round_keys = expand_key(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))
check("Key expansion FIPS-197 A.1: round key 10", bytes(round_keys[10]).hex() == "d014f9a8c9ee2589e13f0cc8b6630ca6")

vectors = [
    ("2b7e151628aed2a6abf7158809cf4f3c", "3243f6a8885a308d313198a2e0370734", "3925841d02dc09fbdc118597196a0b32"),
    ("000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ("000102030405060708090a0b0c0d0e0f1011121314151617", "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191"),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"),
]
for key, plaintext, expected in vectors:
    aes = AES(bytes.fromhex(key))
    ciphertext = aes.encrypt_block(bytes.fromhex(plaintext))
    check(f"FIPS-197 AES-{len(key) * 4} enkripsi", ciphertext.hex() == expected)
    check(f"FIPS-197 AES-{len(key) * 4} dekripsi", aes.decrypt_block(ciphertext).hex() == plaintext)

cbc = AES(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))
first_block = cbc.encrypt_cbc(bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"), bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
check("NIST SP 800-38A CBC blok pertama", first_block[:16].hex() == "7649abac8119b246cee98e9b12e9197d")

check("ECB ASCII cocok dengan OpenSSL (key abcdefghijklmnop, plaintext halo)",
      encrypt("halo", "abcdefghijklmnop", "ECB") == "95eeb89f84facc9afe32ee7c685210c6")

check("PKCS#7: 4 byte data ditambah 12 byte bernilai 0x0c", pad(b"halo") == b"halo" + bytes([12] * 12))
check("PKCS#7: 16 byte data ditambah satu blok penuh", len(pad(b"a" * 16)) == 32)
check("unpad(pad(x)) == x", unpad(pad(b"Keamanan Informasi")) == b"Keamanan Informasi")

messages = ["Halo Bob", "Halo Alice", "spasi   di tengah", "Angka 12345 & simbol !@#$%^&*()_+-=[]{};:'\",.<>/?", "x" * 16]
keys = ["kuncirahasia1234", "kunci rahasia 24 karakter"[:24], "K" * 32]
for key in keys:
    for mode in ("CBC", "ECB"):
        for message in messages:
            check(f"AES-{len(key) * 8}-{mode} round trip {message[:12]!r}", decrypt(encrypt(message, key, mode), key, mode) == message)

check("CBC: pesan sama menghasilkan ciphertext berbeda", encrypt("halo", keys[0]) != encrypt("halo", keys[0]))
check("ECB: pesan sama menghasilkan ciphertext sama", encrypt("halo", keys[0], "ECB") == encrypt("halo", keys[0], "ECB"))
check("Key 15 karakter ditolak", raises(encrypt, "halo", "a" * 15))
check("Key non-ASCII ditolak", raises(encrypt, "halo", "kuncirahasia123é"))
check("Plaintext non-ASCII ditolak", raises(encrypt, "héllo", keys[0]))
check("Key salah gagal didekripsi", raises(unseal, encrypt("rahasia", keys[0]), "kunciyangsalah!!", "Pesan"))

kdc = KeyDistributionCenter()
kdc.register("alice", "masterkeyalice01")
kdc.register("bob", "masterkey-bob-02")
session_key, ticket, response = kdc.issue(join("alice", "bob", 4242))
ks, id_a, id_b, nonce, ticket_for_bob = split(unseal(response, "masterkeyalice01", "Respons"), 5)
check("Langkah 2: Alice membuka respons dengan Ka", (ks, id_a, id_b, nonce) == (session_key, "alice", "bob", "4242"))
check("Langkah 2: ticket di dalam respons sama dengan yang dibuat KDC", ticket_for_bob == ticket)
check("Langkah 2: Alice tidak bisa membuka ticket", raises(unseal, ticket, "masterkeyalice01", "Ticket"))
check("Langkah 3: Bob membuka ticket dengan Kb", split(unseal(ticket, "masterkey-bob-02", "Ticket"), 2) == [session_key, "alice"])
check("Langkah 5: f(N2) = N2 + 1", transform(41) == 42 and transform(2**32 - 1) == 0)
check("KDC menolak ID yang tidak terdaftar", raises(kdc.issue, join("alice", "carol", 1)))
check("KDC menolak request dengan format salah", raises(kdc.issue, "alice||bob"))
kdc.fixed_session_key = "SesiTetap123456789012345"
check("Session key tetap dari KDC dipakai (AES-192)", kdc.issue(join("alice", "bob", 1))[0] == "SesiTetap123456789012345")
check("ProtocolError turunan ValueError", issubclass(ProtocolError, ValueError))

print(f"\nSemua {passed} test lulus.")
