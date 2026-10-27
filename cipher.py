import secrets

from aes import AES, BLOCK_SIZE, split_blocks

KEY_LENGTHS = (16, 24, 32)
MODES = ("CBC", "ECB")


def to_ascii(text, label="Teks"):
    try:
        return text.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError(f"{label} harus berupa karakter ASCII") from None


def validate_key(key):
    to_ascii(key, "Key")
    if len(key) not in KEY_LENGTHS:
        raise ValueError(f"Key harus 16, 24, atau 32 karakter ASCII (sekarang {len(key)})")
    if not key.isprintable():
        raise ValueError("Key hanya boleh berisi karakter ASCII yang dapat dicetak")
    return key


def validate_mode(mode):
    if mode not in MODES:
        raise ValueError(f"Mode harus salah satu dari {', '.join(MODES)}")
    return mode


def cipher_name(key, mode):
    return f"AES-{len(key) * 8}-{mode}"


def encrypt(plaintext, key, mode="CBC"):
    aes = AES(to_ascii(validate_key(key)))
    data = to_ascii(plaintext, "Plaintext")
    if validate_mode(mode) == "ECB":
        return aes.encrypt_ecb(data).hex()
    iv = secrets.token_bytes(BLOCK_SIZE)
    return (aes.encrypt_block(iv) + aes.encrypt_cbc(data, iv)).hex()


def decrypt(ciphertext, key, mode="CBC"):
    aes = AES(to_ascii(validate_key(key)))
    blocks = split_blocks(bytes.fromhex(ciphertext))
    if validate_mode(mode) == "ECB":
        plaintext = aes.decrypt_ecb(b"".join(blocks))
    else:
        plaintext = aes.decrypt_cbc(b"".join(blocks[1:]), aes.decrypt_block(blocks[0]))
    return plaintext.decode("ascii")
