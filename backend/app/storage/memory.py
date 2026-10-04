from .base import ObjectNotFound, StorageService, validate_key


class MemoryStorage(StorageService):
    """In-memory storage used by the test suite. Never used in production."""

    provider = "memory"

    def __init__(self, bucket="test-bucket"):
        self.bucket = bucket
        self._objects = {}

    def check(self):
        return True

    def ensure_bucket(self):
        return None

    def put_object(self, key, data, content_type=None):
        validate_key(key)
        self._objects[key] = bytes(data) if isinstance(data, (bytes, bytearray)) else data.read()

    def get_object(self, key):
        validate_key(key)
        try:
            return self._objects[key]
        except KeyError:
            raise ObjectNotFound(key) from None

    def delete_object(self, key):
        validate_key(key)
        self._objects.pop(key, None)

    def object_exists(self, key):
        validate_key(key)
        return key in self._objects

    def generate_download_url(self, key, expires_in=300, filename=None):
        validate_key(key)
        return f"memory://{self.bucket}/{key}?expires={int(expires_in)}"