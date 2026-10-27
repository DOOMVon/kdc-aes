import secrets
import string

from cipher import decrypt, validate_key

SEPARATOR = "||"
SESSION_KEY_CHARACTERS = string.ascii_letters + string.digits


class ProtocolError(ValueError):
    pass


def join(*fields):
    return SEPARATOR.join(str(field) for field in fields)


def split(text, count):
    fields = text.split(SEPARATOR)
    if len(fields) != count:
        raise ProtocolError(f"Format pesan tidak sesuai, diharapkan {count} field")
    return fields


def validate_identity(user_id):
    if not user_id.isascii() or not user_id.isalnum():
        raise ValueError("ID hanya boleh berisi huruf dan angka ASCII")
    return user_id


def validate_session_key(key):
    if "|" in validate_key(key):
        raise ValueError("Session key tidak boleh mengandung karakter '|'")
    return key


def new_session_key(length=16):
    return "".join(secrets.choice(SESSION_KEY_CHARACTERS) for _ in range(length))


def new_nonce():
    return secrets.randbits(32)


def transform(nonce):
    return (nonce + 1) % 2**32


def read_nonce(text):
    if not text.isdigit():
        raise ProtocolError("Nonce harus berupa bilangan")
    return int(text)


def unseal(ciphertext, key, label):
    try:
        return decrypt(ciphertext, key)
    except ValueError:
        raise ProtocolError(f"{label} tidak dapat didekripsi, key tidak cocok") from None
