from flask import current_app

from .base import (  # noqa: F401
    ObjectNotFound,
    StorageConfigError,
    StorageError,
    StorageService,
    validate_key,
)
from .memory import MemoryStorage
from .minio_storage import MinIOStorage
from .s3 import S3Storage


def _missing(config, names):
    return [name for name in names if not config.get(name)]


def _build(config):
    provider = (config.get("STORAGE_PROVIDER") or "").lower()

    if provider == "memory":
        return MemoryStorage()

    if provider == "minio":
        missing = _missing(
            config, ("MINIO_ENDPOINT", "MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD", "MINIO_BUCKET")
        )
        if missing:
            raise StorageConfigError("Missing storage settings: " + ", ".join(missing))
        storage = MinIOStorage(
            endpoint=config["MINIO_ENDPOINT"],
            bucket=config["MINIO_BUCKET"],
            access_key=config["MINIO_ROOT_USER"],
            secret_key=config["MINIO_ROOT_PASSWORD"],
            use_ssl=config.get("MINIO_USE_SSL", False),
            region=config.get("AWS_REGION") or "us-east-1",
        )
        storage.ensure_bucket()
        return storage

    if provider == "s3":
        missing = _missing(config, ("AWS_S3_BUCKET",))
        if missing:
            raise StorageConfigError("Missing storage settings: " + ", ".join(missing))
        storage = S3Storage(
            bucket=config["AWS_S3_BUCKET"],
            region=config.get("AWS_REGION") or "us-east-1",
            access_key=config.get("AWS_ACCESS_KEY_ID"),
            secret_key=config.get("AWS_SECRET_ACCESS_KEY"),
        )
        storage.ensure_bucket()
        return storage

    raise StorageConfigError(f"Unknown STORAGE_PROVIDER '{provider}'. Use minio, s3 or memory.")


def get_storage():
    """Return the shared storage service, building it on first use."""
    service = current_app.extensions.get("storage_service")
    if service is None:
        service = _build(current_app.config)
        current_app.extensions["storage_service"] = service
    return service