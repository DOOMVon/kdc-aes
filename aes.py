BLOCK_SIZE = 16
ROUNDS = {16: 10, 24: 12, 32: 14}
MIX_MATRIX = ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))
INV_MIX_MATRIX = ((14, 11, 13, 9), (9, 14, 11, 13), (13, 9, 14, 11), (11, 13, 9, 14))


def xtime(value):
    value <<= 1
    return value ^ 0x11B if value & 0x100 else value


def gf_multiply(a, b):
    product = 0
    while b:
        if b & 1:
            product ^= a
        a = xtime(a)
        b >>= 1
    return product


def gf_inverse(value):
    result, base, exponent = 1, value, 254
    while exponent:
        if exponent & 1:
            result = gf_multiply(result, base)
        base = gf_multiply(base, base)
        exponent >>= 1
    return result


def rotate_byte(value, shift):
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


def affine_transform(value):
    return value ^ rotate_byte(value, 1) ^ rotate_byte(value, 2) ^ rotate_byte(value, 3) ^ rotate_byte(value, 4) ^ 0x63


S_BOX = [affine_transform(gf_inverse(value)) for value in range(256)]
INV_S_BOX = [S_BOX.index(value) for value in range(256)]


def xor(left, right):
    return [a ^ b for a, b in zip(left, right)]


def sub_bytes(state, box):
    return [box[byte] for byte in state]


def shift_rows(state, direction=1):
    return [state[row + 4 * ((column + direction * row) % 4)] for column in range(4) for row in range(4)]


def mix_columns(state, matrix):
    mixed = []
    for column in range(4):
        values = state[4 * column:4 * column + 4]
        for coefficients in matrix:
            byte = 0
            for coefficient, value in zip(coefficients, values):
                byte ^= gf_multiply(coefficient, value)
            mixed.append(byte)
    return mixed


def add_round_key(state, round_key):
    return xor(state, round_key)


def expand_key(key):
    words_in_key = len(key) // 4
    total_words = 4 * (ROUNDS[len(key)] + 1)
    words = [list(key[i:i + 4]) for i in range(0, len(key), 4)]
    round_constant = 1
    for index in range(words_in_key, total_words):
        word = words[index - 1]
        if index % words_in_key == 0:
            word = sub_bytes(word[1:] + word[:1], S_BOX)
            word[0] ^= round_constant
            round_constant = xtime(round_constant)
        elif words_in_key > 6 and index % words_in_key == 4:
            word = sub_bytes(word, S_BOX)
        words.append(xor(words[index - words_in_key], word))
    return [sum(words[i:i + 4], []) for i in range(0, total_words, 4)]


def pad(data):
    size = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([size] * size)


def unpad(data):
    size = data[-1]
    if not 1 <= size <= BLOCK_SIZE or data[-size:] != bytes([size] * size):
        raise ValueError("Padding tidak valid (key salah atau ciphertext rusak)")
    return data[:-size]


def split_blocks(data):
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError("Panjang ciphertext harus kelipatan 16 byte")
    return [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


class AES:
    def __init__(self, key):
        if len(key) not in ROUNDS:
            raise ValueError("Key AES harus 16, 24, atau 32 byte")
        self.round_keys = expand_key(key)

    def encrypt_block(self, block):
        state = add_round_key(list(block), self.round_keys[0])
        for round_key in self.round_keys[1:-1]:
            state = sub_bytes(state, S_BOX)
            state = shift_rows(state)
            state = mix_columns(state, MIX_MATRIX)
            state = add_round_key(state, round_key)
        state = shift_rows(sub_bytes(state, S_BOX))
        return bytes(add_round_key(state, self.round_keys[-1]))

    def decrypt_block(self, block):
        state = add_round_key(list(block), self.round_keys[-1])
        for round_key in reversed(self.round_keys[1:-1]):
            state = sub_bytes(shift_rows(state, -1), INV_S_BOX)
            state = add_round_key(state, round_key)
            state = mix_columns(state, INV_MIX_MATRIX)
        state = sub_bytes(shift_rows(state, -1), INV_S_BOX)
        return bytes(add_round_key(state, self.round_keys[0]))

    def encrypt_ecb(self, plaintext):
        return b"".join(self.encrypt_block(block) for block in split_blocks(pad(plaintext)))

    def decrypt_ecb(self, ciphertext):
        return unpad(b"".join(self.decrypt_block(block) for block in split_blocks(ciphertext)))

    def encrypt_cbc(self, plaintext, iv):
        previous, output = iv, []
        for block in split_blocks(pad(plaintext)):
            previous = self.encrypt_block(xor(block, previous))
            output.append(previous)
        return b"".join(output)

    def decrypt_cbc(self, ciphertext, iv):
        previous, output = iv, []
        for block in split_blocks(ciphertext):
            output.append(bytes(xor(self.decrypt_block(block), previous)))
            previous = block
        return unpad(b"".join(output))
