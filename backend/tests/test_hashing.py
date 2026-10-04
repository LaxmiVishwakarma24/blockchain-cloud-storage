from app.files.hashing import hashes_match, sha256_hex


def test_sha256_matches_known_vector():
    assert sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_sha256_of_empty_input():
    assert sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_sha256_changes_when_one_byte_changes():
    assert sha256_hex(b"hello") != sha256_hex(b"hellp")


def test_hashes_match_is_case_insensitive_and_strict():
    digest = sha256_hex(b"abc")
    assert hashes_match(digest, digest.upper())
    assert not hashes_match(digest, sha256_hex(b"abd"))