"""
Multi-layer cipher: strong layered encryption using standard libraries with optional AES fallback.

Features:
- PBKDF2-HMAC-SHA256 key derivation with salt and iterations
- zlib compression
- AES-CBC encryption (if PyCryptodome is installed) with PKCS7 padding; otherwise XOR with HMAC-SHA512 keystream
- Columnar transposition cipher layer (key-derived column order)
- Base85 encoding for compact ASCII output
- HMAC-SHA256 authentication tag

Security notes:
- Use a strong, high-entropy password for the key. This script is meant for layered obfuscation and defense-in-depth, but for critical use prefer battle-tested libraries and protocols.
- If PyCryptodome is available, AES-CBC is used (with random IV); otherwise a secure XOR keystream is used.

Usage examples (CLI):
    python multi_layer_cipher.py encrypt -p "my password" -i plaintext.txt -o ciphertext.bin
    python multi_layer_cipher.py decrypt -p "my password" -i ciphertext.bin -o recovered.txt

"""

import argparse
import base64
import binascii
import hashlib
import hmac
import os
import secrets
import struct
import zlib
from typing import Tuple

# Try to import AES from PyCryptodome; optional.
try:
    from Crypto.Cipher import AES
    HAVE_AES = True
except Exception:
    HAVE_AES = False

# ----- Utility primitives -----

def pbkdf2(password: bytes, salt: bytes, iterations: int = 200_000, dklen: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password, salt, iterations, dklen)


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()


# Deterministic keystream generator using HMAC-SHA512 (like an HMAC-DRBG)
def keystream_hmac_sha512(key: bytes, length: int, nonce: bytes = b'') -> bytes:
    out = bytearray()
    counter = 1
    while len(out) < length:
        ctr = struct.pack('>I', counter)
        out.extend(hmac_sha512(key, nonce + ctr))
        counter += 1
    return bytes(out[:length])


# XOR bytes with keystream
def xor_bytes(data: bytes, keystream: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, keystream))


# PKCS7 padding/unpadding for AES
def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError('Invalid padding (empty)')
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError('Invalid padding')
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError('Invalid padding bytes')
    return data[:-pad_len]


# Columnar transposition cipher (key-derived ordering)
def columnar_encrypt(data: bytes, key: bytes) -> bytes:
    # derive order from key digest
    order = list(range(1, len(key) + 1))
    # map ranks by sorting bytes with indices
    ranks = sorted(range(len(key)), key=lambda i: (key[i], i))
    columns = [[] for _ in range(len(key))]
    for i, b in enumerate(data):
        columns[i % len(key)].append(b)
    # reorder columns by rank and then flatten
    ordered = bytearray()
    for idx in ranks:
        ordered.extend(columns[idx])
    return bytes(ordered)


def columnar_decrypt(data: bytes, key: bytes) -> bytes:
    k = len(key)
    full_cols = len(data) // k
    extra = len(data) % k
    ranks = sorted(range(k), key=lambda i: (key[i], i))
    # determine number of items in each column
    col_lens = [full_cols + (1 if i < extra else 0) for i in range(k)]
    # build columns in rank order
    cols = [None] * k
    pos = 0
    for idx in ranks:
        length = col_lens[idx]
        cols[idx] = list(data[pos:pos+length])
        pos += length
    # read row-wise
    out = bytearray()
    for r in range(full_cols + 1):
        for c in range(k):
            if cols[c] and r < len(cols[c]):
                out.append(cols[c][r])
    return bytes(out)


# ----- Layered encrypt/decrypt -----

HEADER_MAGIC = b'MLC01'  # Multi-Layer Cipher v0.1


def encrypt(plaintext: bytes, password: str, iterations: int = 200_000) -> bytes:
    password_b = password.encode('utf-8')
    salt = secrets.token_bytes(16)
    key = pbkdf2(password_b, salt, iterations, dklen=32)

    # 1) compress
    compressed = zlib.compress(plaintext)

    # 2) AES or XOR layer
    iv = secrets.token_bytes(16)
    if HAVE_AES:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        layer1 = cipher.encrypt(pkcs7_pad(compressed))
        mode_flag = b'A'
    else:
        ks = keystream_hmac_sha512(key + b'xor', len(compressed), iv)
        layer1 = xor_bytes(compressed, ks)
        mode_flag = b'X'

    # 3) columnar transposition using key-derived short key
    short_key = hashlib.sha256(key + b'col').digest()[:16]
    layer2 = columnar_encrypt(layer1, short_key)

    # 4) base85 encode
    payload = base64.b85encode(layer2)

    # 5) header: magic + salt + iv + iterations (4 bytes) + mode_flag
    header = HEADER_MAGIC + salt + iv + struct.pack('>I', iterations) + mode_flag

    # 6) compute HMAC over header||payload
    mac_key = pbkdf2(key, b'mac', iterations=100_000, dklen=32)
    tag = hmac_sha256(mac_key, header + payload)

    return header + payload + tag


def decrypt(blob: bytes, password: str) -> bytes:
    if len(blob) < len(HEADER_MAGIC) + 16 + 16 + 4 + 1 + 32:
        raise ValueError('Blob too small or corrupted')
    pos = 0
    magic = blob[pos:pos+len(HEADER_MAGIC)]; pos += len(HEADER_MAGIC)
    if magic != HEADER_MAGIC:
        raise ValueError('Invalid magic header')
    salt = blob[pos:pos+16]; pos += 16
    iv = blob[pos:pos+16]; pos += 16
    iterations = struct.unpack('>I', blob[pos:pos+4])[0]; pos += 4
    mode_flag = blob[pos:pos+1]; pos += 1

    tag = blob[-32:]
    payload = blob[pos:-32]

    password_b = password.encode('utf-8')
    key = pbkdf2(password_b, salt, iterations, dklen=32)
    mac_key = pbkdf2(key, b'mac', iterations=100_000, dklen=32)

    expected = hmac_sha256(mac_key, HEADER_MAGIC + salt + iv + struct.pack('>I', iterations) + mode_flag + payload)
    # constant-time compare
    if not hmac.compare_digest(expected, tag):
        raise ValueError('HMAC verification failed (wrong password or tampered)')

    # reverse base85
    layer2 = base64.b85decode(payload)

    # reverse columnar
    short_key = hashlib.sha256(key + b'col').digest()[:16]
    layer1 = columnar_decrypt(layer2, short_key)

    # reverse AES or XOR
    if mode_flag == b'A':
        if not HAVE_AES:
            raise RuntimeError('Encrypted with AES but AES library not available')
        cipher = AES.new(key, AES.MODE_CBC, iv)
        compressed = pkcs7_unpad(cipher.decrypt(layer1))
    elif mode_flag == b'X':
        ks = keystream_hmac_sha512(key + b'xor', len(layer1), iv)
        compressed = xor_bytes(layer1, ks)
    else:
        raise ValueError('Unknown mode flag')

    # decompress
    plaintext = zlib.decompress(compressed)
    return plaintext


# ----- Simple CLI -----

def main():
    ap = argparse.ArgumentParser(description='Multi-layer cipher (encrypt/decrypt)')
    ap.add_argument('mode', choices=['encrypt', 'decrypt'])
    ap.add_argument('-p', '--password', required=True, help='Password / key phrase')
    ap.add_argument('-i', '--input', required=True, help='Input file path')
    ap.add_argument('-o', '--output', required=True, help='Output file path')
    ap.add_argument('--iter', type=int, default=200_000, help='PBKDF2 iterations (default 200000)')
    args = ap.parse_args()

    data = open(args.input, 'rb').read()
    if args.mode == 'encrypt':
        out = encrypt(data, args.password, iterations=args.iter)
        open(args.output, 'wb').write(out)
        print('Encrypted ->', args.output)
    else:
        out = decrypt(data, args.password)
        open(args.output, 'wb').write(out)
        print('Decrypted ->', args.output)


class basicTools():
    class morse():
        morse_alphabet = {
        'A': '.-',    'B': '-...',  'C': '-.-.',  'D': '-..',
        'E': '.',     'F': '..-.',  'G': '--.',   'H': '....',
        'I': '..',    'J': '.---',  'K': '-.-',   'L': '.-..',
        'M': '--',    'N': '-.',    'O': '---',   'P': '.--.',
        'Q': '--.-',  'R': '.-.',   'S': '...',   'T': '-',
        'U': '..-',   'V': '...-',  'W': '.--',   'X': '-..-',
        'Y': '-.--',  'Z': '--..'
        }
        def encode(string):
            global morse_alphabet
            morse_str = ""
            string = string.lower()
            string.replace("-", " ")
            string .replace(".", " ")
            for char in string:
                if char.isalpha():
                    morse_str+= morse_alphabet[char]
                    morse_str+= " "
                if not char.isalpha():
                    pass

            return string
        def decode(string):
            return string
        
        

if __name__ == '__main__':
    main()
