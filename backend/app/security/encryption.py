import base64
import binascii
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMAT_VERSION = 1
NONCE_SIZE = 12
KEY_SIZE = 32
TAG_SIZE = 16


class EncryptionConfigError(Exception):
    """The encryption key is missing or invalid."""


class DecryptionError(Exception):
    """The data could not be decrypted: wrong key, wrong context or tampering."""


def load_key(value):
    """Decode a base64 string into a 32-byte AES-256 key."""
    text = (value or "").strip()
    if not text:
        raise EncryptionConfigError(
            "ENCRYPTION_KEY is not set. Run 'flask generate-key' and add it to .env."
        )
    text = text.replace("+", "-").replace("/", "_")
    try:
        key = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise EncryptionConfigError("ENCRYPTION_KEY is not valid base64.") from None
    if len(key) != KEY_SIZE:
        raise EncryptionConfigError("ENCRYPTION_KEY must decode to exactly 32 bytes (AES-256).")
    return key


def key_from_config(config):
    return load_key(config.get("ENCRYPTION_KEY"))


def generate_key():
    return base64.urlsafe_b64encode(os.urandom(KEY_SIZE)).decode("ascii")


def encrypt_bytes(key, plaintext, aad):
    """Return version byte + 12-byte nonce + ciphertext + 16-byte auth tag.

    `aad` is authenticated but not encrypted. It binds the ciphertext to its storage location.
    """
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return bytes([FORMAT_VERSION]) + nonce + ciphertext


def decrypt_bytes(key, blob, aad):
    if len(blob) < 1 + NONCE_SIZE + TAG_SIZE or blob[0] != FORMAT_VERSION:
        raise DecryptionError("Unrecognised encrypted data format.")
    nonce = blob[1 : 1 + NONCE_SIZE]
    try:
        return AESGCM(key).decrypt(nonce, blob[1 + NONCE_SIZE :], aad)
    except InvalidTag:
        raise DecryptionError("Authentication failed.") from None