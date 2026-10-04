import re
from abc import ABC, abstractmethod


class StorageError(Exception):
    """The storage backend failed."""


class StorageConfigError(StorageError):
    """Storage settings are missing or invalid."""


class ObjectNotFound(StorageError):
    """The object key does not exist."""


_BAD_CHARS = re.compile(r"[\x00-\x1f\x7f\\]")


def validate_key(key):
    """Reject keys that could escape a prefix or confuse the backend."""
    if not isinstance(key, str) or not key or len(key.encode("utf-8")) > 1024:
        raise ValueError("Invalid object key.")
    if key.startswith("/") or _BAD_CHARS.search(key):
        raise ValueError("Invalid object key.")
    if any(part in ("", ".", "..") for part in key.split("/")):
        raise ValueError("Invalid object key.")
    return key


class StorageService(ABC):
    """Same interface for AWS S3, MinIO and the in-memory test double."""

    provider = "abstract"
    bucket = ""

    @abstractmethod
    def check(self):
        """Return True if the bucket is reachable."""

    @abstractmethod
    def ensure_bucket(self):
        """Make sure the (private) bucket is ready to use."""

    @abstractmethod
    def put_object(self, key, data, content_type=None):
        """Store bytes or a file-like object under `key`."""

    @abstractmethod
    def get_object(self, key):
        """Return the object's bytes. Raises ObjectNotFound."""

    @abstractmethod
    def delete_object(self, key):
        """Delete the object (no error if it is already gone)."""

    @abstractmethod
    def object_exists(self, key):
        """Return True if the key exists."""

    @abstractmethod
    def generate_download_url(self, key, expires_in=300, filename=None):
        """Return a temporary signed URL for downloading the object."""