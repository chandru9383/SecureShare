import hashlib
import os
import base64
from Crypto.Cipher import AES

def encrypt_data(data: bytes, password: str = "") -> str:
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000, dklen=32)
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    combined = salt + nonce + tag + ciphertext
    return base64.b64encode(combined).decode("utf-8")

def decrypt_data(encoded_data: str, password: str = "") -> bytes:
    raw = base64.b64decode(encoded_data)
    salt = raw[:16]
    nonce = raw[16:28]
    tag = raw[28:44]
    ciphertext = raw[44:]
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000, dklen=32)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except ValueError:
        raise ValueError("Incorrect password or corrupted data")