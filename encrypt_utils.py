# encrypt_utils.py
"""
AES-GCM encryption utilities for Privacy-Preserving LBS Project.
Supports:
 - Raw key generation / wrapping / unwrapping
 - PBKDF2-based key derivation from passphrase
 - High-level encrypt/decrypt helpers (used in Flask backend)
"""

import base64
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

# ======================
# CONFIG
# ======================
PBKDF2_ITERS = 200_000
AES_SALT = b"plqp-salt-2025"  # static salt for derivation demo; in production, generate per key


# ======================
# LOW-LEVEL HELPERS
# ======================
def gen_raw_key() -> bytes:
    """Generate a random 256-bit AES key."""
    return get_random_bytes(32)


def derive_kek(passphrase: str, salt: bytes, iterations=PBKDF2_ITERS) -> bytes:
    """Derive a key-encryption key (KEK) from a passphrase."""
    return PBKDF2(passphrase.encode("utf-8"), salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)


def encrypt_with_key(key: bytes, plaintext: bytes) -> str:
    """AES-GCM encrypt; return base64(nonce + tag + ciphertext)."""
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    token = base64.b64encode(nonce + tag + ct).decode("utf-8")
    return token


def decrypt_with_key(key: bytes, token_b64: str) -> bytes:
    """AES-GCM decrypt from base64(nonce + tag + ciphertext)."""
    data = base64.b64decode(token_b64)
    nonce = data[:12]
    tag = data[12:28]
    ct = data[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)


# ======================
# KEY WRAP / UNWRAP
# ======================
def wrap_key_with_passphrase(raw_key: bytes, passphrase: str, path: str):
    """Encrypt (wrap) a raw AES key using a passphrase and save it to file."""
    salt = get_random_bytes(16)
    kek = derive_kek(passphrase, salt)
    token = encrypt_with_key(kek, raw_key)
    payload = base64.b64encode(salt).decode("utf-8") + "." + token
    with open(path, "w") as f:
        f.write(payload)


def unwrap_key_with_passphrase(passphrase: str, path: str) -> bytes:
    """Decrypt (unwrap) an AES key from a file encrypted with wrap_key_with_passphrase()."""
    with open(path, "r") as f:
        payload = f.read().strip()
    salt_b64, token = payload.split(".", 1)
    salt = base64.b64decode(salt_b64)
    kek = derive_kek(passphrase, salt)
    raw_key = decrypt_with_key(kek, token)
    return raw_key


# ======================
# FILE ENCRYPT/DECRYPT
# ======================
def encrypt_file_with_keyfile(raw_key: bytes, infile: str, outfile: str):
    data = open(infile, "rb").read()
    token = encrypt_with_key(raw_key, data)
    with open(outfile, "w") as f:
        f.write(token)


def decrypt_file_with_keyfile(raw_key: bytes, infile: str, outfile: str):
    token = open(infile, "r").read()
    data = decrypt_with_key(raw_key, token)
    with open(outfile, "wb") as f:
        f.write(data)


# ======================
# HIGH-LEVEL HELPERS (used by Flask)
# ======================
def derive_key_from_passphrase(passphrase: str, salt: bytes = AES_SALT, key_len: int = 32) -> bytes:
    """Derive a 256-bit AES key from a user passphrase (used by backend)."""
    if isinstance(passphrase, str):
        passphrase = passphrase.encode("utf-8")
    return PBKDF2(passphrase, salt, dkLen=key_len, count=PBKDF2_ITERS, hmac_hash_module=SHA256)


def encrypt_bytes_aes_gcm(plaintext_bytes: bytes, key_bytes: bytes):
    """Encrypt and return dict with hex-encoded nonce/tag/ciphertext."""
    nonce = get_random_bytes(12)
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext_bytes)
    return {
        "nonce_hex": nonce.hex(),
        "tag_hex": tag.hex(),
        "ciphertext_hex": ct.hex(),
    }


def decrypt_bytes_aes_gcm(nonce_hex: str, tag_hex: str, ciphertext_hex: str, key_bytes: bytes) -> bytes:
    """Decrypt from hex fields (inverse of encrypt_bytes_aes_gcm)."""
    nonce = bytes.fromhex(nonce_hex)
    tag = bytes.fromhex(tag_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext,tag)