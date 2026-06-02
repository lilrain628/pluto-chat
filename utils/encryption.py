import base64
import hashlib
import os

from utils.caesar_cipher import caesar_decrypt, caesar_encrypt

ENCRYPTION_CAESAR = "caesar"
ENCRYPTION_AES128 = "aes128"
DEFAULT_ENCRYPTION_PROTOCOL = ENCRYPTION_CAESAR

_AES128_KEY_SIZE = 16
_AES128_SALT_SIZE = 16
_AES_GCM_NONCE_SIZE = 12
_PBKDF2_ITERATIONS = 200000


def normalize_encryption_protocol(protocol):
    value = str(protocol or DEFAULT_ENCRYPTION_PROTOCOL).strip().lower()
    value = value.replace("-", "").replace("_", "")

    if value in ("1", "caesar", "cesar"):
        return ENCRYPTION_CAESAR
    if value in ("2", "aes", "aes128", "aesgcm", "aes128gcm"):
        return ENCRYPTION_AES128

    raise ValueError(f"Unknown encryption protocol: {protocol}")


def encrypt_message(message, protocol=DEFAULT_ENCRYPTION_PROTOCOL, key=None):
    protocol = normalize_encryption_protocol(protocol)
    if protocol == ENCRYPTION_CAESAR:
        return caesar_encrypt(message)
    if protocol == ENCRYPTION_AES128:
        return _aes128_encrypt(message, key)
    raise ValueError(f"Unsupported encryption protocol: {protocol}")


def decrypt_message(message, protocol=DEFAULT_ENCRYPTION_PROTOCOL, key=None):
    protocol = normalize_encryption_protocol(protocol)
    if protocol == ENCRYPTION_CAESAR:
        return caesar_decrypt(message)
    if protocol == ENCRYPTION_AES128:
        return _aes128_decrypt(message, key)
    raise ValueError(f"Unsupported encryption protocol: {protocol}")


def _aes128_encrypt(message, password):
    AESGCM = _load_aesgcm()
    salt = os.urandom(_AES128_SALT_SIZE)
    nonce = os.urandom(_AES_GCM_NONCE_SIZE)
    aesgcm = AESGCM(_derive_aes128_key(password, salt))
    ciphertext = aesgcm.encrypt(nonce, message.encode("utf-8"), None)
    return _base32_encode(salt + nonce + ciphertext)


def _aes128_decrypt(message, password):
    AESGCM = _load_aesgcm()
    payload = _base32_decode(message)
    min_payload_size = _AES128_SALT_SIZE + _AES_GCM_NONCE_SIZE + 16
    if len(payload) < min_payload_size:
        raise ValueError("AES-128 message is too short")

    salt = payload[:_AES128_SALT_SIZE]
    nonce_start = _AES128_SALT_SIZE
    nonce_end = nonce_start + _AES_GCM_NONCE_SIZE
    nonce = payload[nonce_start:nonce_end]
    ciphertext = payload[nonce_end:]

    aesgcm = AESGCM(_derive_aes128_key(password, salt))
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


def _derive_aes128_key(password, salt):
    if password is None or str(password) == "":
        raise ValueError("AES-128 requires a password")
    return hashlib.pbkdf2_hmac(
        "sha256",
        str(password).encode("utf-8"),
        salt,
        _PBKDF2_ITERATIONS,
        dklen=_AES128_KEY_SIZE,
    )


def _base32_encode(data):
    return base64.b32encode(data).decode("ascii").rstrip("=")


def _base32_decode(text):
    value = str(text).strip().upper()
    padding = "=" * (-len(value) % 8)
    return base64.b32decode(value + padding, casefold=True)


def _load_aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as error:
        raise RuntimeError("AES-128 requires the cryptography package") from error
    return AESGCM
