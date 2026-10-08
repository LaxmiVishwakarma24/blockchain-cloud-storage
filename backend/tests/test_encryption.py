import base64

import pytest

from app.security.encryption import (
    DecryptionError,
    EncryptionConfigError,
    decrypt_bytes,
    encrypt_bytes,
    generate_key,
    load_key,
)

KEY = bytes(range(32))
AAD = b"users/1/abc"


def test_roundtrip():
    blob = encrypt_bytes(KEY, b"secret data", AAD)
    assert decrypt_bytes(KEY, blob, AAD) == b"secret data"


def test_blob_layout_and_no_plaintext_leak():
    plaintext = b"very confidential text"
    blob = encrypt_bytes(KEY, plaintext, AAD)
    assert blob[0] == 1
    assert len(blob) == 1 + 12 + len(plaintext) + 16
    assert plaintext not in blob


def test_fresh_nonce_for_every_encryption():
    first = encrypt_bytes(KEY, b"same input", AAD)
    second = encrypt_bytes(KEY, b"same input", AAD)
    assert first != second
    assert first[1:13] != second[1:13]


def test_wrong_key_fails():
    blob = encrypt_bytes(KEY, b"data", AAD)
    with pytest.raises(DecryptionError):
        decrypt_bytes(bytes(reversed(KEY)), blob, AAD)


def test_tampered_ciphertext_fails():
    blob = bytearray(encrypt_bytes(KEY, b"some data to protect", AAD))
    blob[20] ^= 0x01
    with pytest.raises(DecryptionError):
        decrypt_bytes(KEY, bytes(blob), AAD)


def test_wrong_context_fails():
    blob = encrypt_bytes(KEY, b"data", AAD)
    with pytest.raises(DecryptionError):
        decrypt_bytes(KEY, blob, b"users/2/other")


def test_truncated_blob_fails():
    blob = encrypt_bytes(KEY, b"data", AAD)
    with pytest.raises(DecryptionError):
        decrypt_bytes(KEY, blob[:10], AAD)


def test_unknown_format_version_fails():
    blob = encrypt_bytes(KEY, b"data", AAD)
    with pytest.raises(DecryptionError):
        decrypt_bytes(KEY, bytes([9]) + blob[1:], AAD)


def test_empty_plaintext_roundtrip():
    assert decrypt_bytes(KEY, encrypt_bytes(KEY, b"", AAD), AAD) == b""


def test_generated_key_is_loadable_and_32_bytes():
    assert len(load_key(generate_key())) == 32


def test_load_key_accepts_standard_base64():
    assert load_key(base64.b64encode(KEY).decode()) == KEY


@pytest.mark.parametrize(
    "bad", ["", "   ", "short", "%%%%", base64.b64encode(b"x" * 16).decode(), None]
)
def test_load_key_rejects_bad_values(bad):
    with pytest.raises(EncryptionConfigError):
        load_key(bad)