import re
from dataclasses import dataclass

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_ZIP_SIGNATURE = [b"PK\x03\x04"]

_OFFICE = {
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}

# extension -> canonical MIME type, MIME types a browser may send, and file signatures.
# `signatures: None` means a plain-text file (checked as UTF-8 without NUL bytes).
ALLOWED_TYPES = {
    "pdf": {"mime": "application/pdf", "accepted": {"application/pdf"}, "signatures": [b"%PDF-"]},
    "png": {"mime": "image/png", "accepted": {"image/png"}, "signatures": [b"\x89PNG\r\n\x1a\n"]},
    "jpg": {"mime": "image/jpeg", "accepted": {"image/jpeg"}, "signatures": [b"\xff\xd8\xff"]},
    "jpeg": {"mime": "image/jpeg", "accepted": {"image/jpeg"}, "signatures": [b"\xff\xd8\xff"]},
    "gif": {"mime": "image/gif", "accepted": {"image/gif"}, "signatures": [b"GIF87a", b"GIF89a"]},
    "txt": {"mime": "text/plain", "accepted": {"text/plain"}, "signatures": None},
    "csv": {
        "mime": "text/csv",
        "accepted": {"text/csv", "text/plain", "application/vnd.ms-excel"},
        "signatures": None,
    },
}
for _ext, _mime in _OFFICE.items():
    ALLOWED_TYPES[_ext] = {"mime": _mime, "accepted": {_mime}, "signatures": _ZIP_SIGNATURE}


class UploadValidationError(Exception):
    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.status_code = status_code


@dataclass
class ValidatedUpload:
    name: str
    extension: str
    mime_type: str


def clean_filename(raw):
    """Keep only the final path component and drop control characters."""
    if not raw:
        raise UploadValidationError("A file name is required.")
    name = raw.replace("\\", "/").split("/")[-1]
    name = _CONTROL.sub("", name).strip().rstrip(". ")
    if not name or len(name) > 200:
        raise UploadValidationError("The file name is empty or too long.")
    return name


def file_extension(name):
    if "." not in name:
        raise UploadValidationError("The file needs an extension.", 415)
    stem, extension = name.rsplit(".", 1)
    if not stem:
        raise UploadValidationError("The file name is not valid.")
    return extension.lower()


def validate_upload(filename, declared_mime, data, max_bytes):
    """Check name, extension, size, declared MIME type and file signature."""
    name = clean_filename(filename)
    extension = file_extension(name)
    spec = ALLOWED_TYPES.get(extension)
    if spec is None:
        raise UploadValidationError(f"Files of type .{extension[:10]} are not allowed.", 415)

    if len(data) == 0:
        raise UploadValidationError("The file is empty.")
    if len(data) > max_bytes:
        raise UploadValidationError("The file is too large.", 413)

    declared = (declared_mime or "").split(";")[0].strip().lower()
    if declared and declared != "application/octet-stream" and declared not in spec["accepted"]:
        raise UploadValidationError("The file type does not match its extension.", 415)

    signatures = spec["signatures"]
    if signatures is None:
        if b"\x00" in data:
            raise UploadValidationError("The text file contains binary data.", 415)
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            raise UploadValidationError("The text file is not valid UTF-8.", 415) from None
    elif not any(data.startswith(signature) for signature in signatures):
        raise UploadValidationError("The file content does not match its extension.", 415)

    return ValidatedUpload(name=name, extension=extension, mime_type=spec["mime"])