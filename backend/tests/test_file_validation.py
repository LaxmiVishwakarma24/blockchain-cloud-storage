import pytest

from app.files.validation import UploadValidationError, clean_filename, validate_upload

PDF = b"%PDF-1.4\n%test\n"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
LIMIT = 1024 * 1024


def check(name, mime, data, limit=LIMIT):
    return validate_upload(name, mime, data, limit)


def test_accepts_valid_pdf():
    upload = check("report.pdf", "application/pdf", PDF)
    assert upload.extension == "pdf"
    assert upload.mime_type == "application/pdf"
    assert upload.name == "report.pdf"


def test_accepts_octet_stream_when_signature_is_right():
    assert check("image.png", "application/octet-stream", PNG).mime_type == "image/png"


def test_accepts_plain_text():
    assert check("notes.txt", "text/plain", "héllo".encode("utf-8")).extension == "txt"


@pytest.mark.parametrize(
    "name", ["virus.exe", "script.js", "page.html", "archive.zip", "noextension", ".pdf"]
)
def test_rejects_disallowed_names(name):
    with pytest.raises(UploadValidationError) as caught:
        check(name, None, PDF)
    assert caught.value.status_code in (400, 415)


def test_rejects_content_that_does_not_match_extension():
    with pytest.raises(UploadValidationError) as caught:
        check("fake.pdf", "application/pdf", PNG)
    assert caught.value.status_code == 415


def test_rejects_wrong_declared_mime_type():
    with pytest.raises(UploadValidationError) as caught:
        check("report.pdf", "image/png", PDF)
    assert caught.value.status_code == 415


def test_rejects_empty_and_oversized_files():
    with pytest.raises(UploadValidationError) as empty:
        check("a.pdf", None, b"")
    assert empty.value.status_code == 400
    with pytest.raises(UploadValidationError) as big:
        check("a.pdf", None, PDF + b"x" * 100, limit=50)
    assert big.value.status_code == 413


def test_text_files_must_be_utf8_without_nul_bytes():
    with pytest.raises(UploadValidationError):
        check("a.txt", None, b"abc\x00def")
    with pytest.raises(UploadValidationError):
        check("a.txt", None, b"\xff\xfe\xfa")


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("..\\..\\secret.pdf", "secret.pdf"),
        ("/etc/passwd.txt", "passwd.txt"),
        ("a/b/c.pdf", "c.pdf"),
        ("report.pdf. ", "report.pdf"),
    ],
)
def test_clean_filename_strips_paths(raw, expected):
    assert clean_filename(raw) == expected


def test_clean_filename_rejects_empty_names():
    with pytest.raises(UploadValidationError):
        clean_filename("   ")