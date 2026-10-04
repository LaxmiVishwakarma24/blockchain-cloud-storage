from unittest.mock import patch

import pytest
from botocore.exceptions import ClientError

from app.storage import (
    MemoryStorage,
    MinIOStorage,
    ObjectNotFound,
    S3Storage,
    StorageConfigError,
    StorageError,
    get_storage,
)
from app.storage.base import validate_key


def client_error(code):
    return ClientError({"Error": {"Code": code, "Message": "x"}}, "Operation")


def make_s3(**kwargs):
    with patch("app.storage.s3.boto3.client") as factory:
        storage = S3Storage(bucket="b", **kwargs)
    return storage, factory.return_value


@pytest.mark.parametrize(
    "key",
    ["", "/abs", "a/../b", "../x", "a//b", "a/./b", "a\\b", "a\x00b", "a/", "x" * 2000],
)
def test_validate_key_rejects_unsafe_keys(key):
    with pytest.raises(ValueError):
        validate_key(key)


def test_validate_key_accepts_normal_keys():
    assert validate_key("files/12/v1.bin") == "files/12/v1.bin"


def test_memory_storage_roundtrip():
    storage = MemoryStorage()
    storage.put_object("a/b.bin", b"hello")
    assert storage.object_exists("a/b.bin")
    assert storage.get_object("a/b.bin") == b"hello"
    storage.delete_object("a/b.bin")
    assert not storage.object_exists("a/b.bin")
    with pytest.raises(ObjectNotFound):
        storage.get_object("a/b.bin")


def test_s3_put_object_sends_bucket_key_and_body():
    storage, client = make_s3()
    storage.put_object("f/1", b"data", content_type="text/plain")
    client.put_object.assert_called_once_with(
        Bucket="b", Key="f/1", Body=b"data", ContentType="text/plain"
    )


def test_s3_put_object_rejects_bad_key():
    storage, client = make_s3()
    with pytest.raises(ValueError):
        storage.put_object("../evil", b"x")
    client.put_object.assert_not_called()


def test_s3_get_missing_object_raises_not_found():
    storage, client = make_s3()
    client.get_object.side_effect = client_error("NoSuchKey")
    with pytest.raises(ObjectNotFound):
        storage.get_object("f/1")


def test_s3_other_errors_become_storage_error():
    storage, client = make_s3()
    client.get_object.side_effect = client_error("AccessDenied")
    with pytest.raises(StorageError) as caught:
        storage.get_object("f/1")
    assert not isinstance(caught.value, ObjectNotFound)


def test_s3_signed_url_is_short_lived():
    storage, client = make_s3()
    client.generate_presigned_url.return_value = "https://signed.example"
    url = storage.generate_download_url("f/1", expires_in=99999, filename='re"port.pdf')
    assert url == "https://signed.example"
    _, kwargs = client.generate_presigned_url.call_args
    assert kwargs["ExpiresIn"] == 3600
    assert 'filename="report.pdf"' in kwargs["Params"]["ResponseContentDisposition"]


def test_s3_ensure_bucket_never_creates_buckets():
    storage, client = make_s3()
    client.head_bucket.side_effect = client_error("404")
    with pytest.raises(StorageError):
        storage.ensure_bucket()
    client.create_bucket.assert_not_called()


def test_minio_uses_path_style_endpoint_and_creates_missing_bucket():
    with patch("app.storage.s3.boto3.client") as factory:
        storage = MinIOStorage(endpoint="localhost:9000", bucket="b", access_key="k", secret_key="s")
    assert factory.call_args.kwargs["endpoint_url"] == "http://localhost:9000"
    client = factory.return_value
    client.head_bucket.side_effect = client_error("404")
    storage.ensure_bucket()
    client.create_bucket.assert_called_once_with(Bucket="b")


def test_minio_does_not_recreate_existing_bucket():
    with patch("app.storage.s3.boto3.client") as factory:
        storage = MinIOStorage(endpoint="localhost:9000", bucket="b", access_key="k", secret_key="s")
    storage.ensure_bucket()
    factory.return_value.create_bucket.assert_not_called()


def test_get_storage_returns_memory_provider_and_caches(app):
    first = get_storage()
    assert isinstance(first, MemoryStorage)
    assert get_storage() is first


def test_get_storage_rejects_unknown_provider(app):
    app.config["STORAGE_PROVIDER"] = "ftp"
    with pytest.raises(StorageConfigError):
        get_storage()


def test_minio_requires_credentials(app):
    app.config.update(STORAGE_PROVIDER="minio", MINIO_ROOT_USER="", MINIO_ROOT_PASSWORD="")
    with pytest.raises(StorageConfigError):
        get_storage()


def test_storage_health_endpoint(client):
    r = client.get("/api/health/storage")
    assert r.status_code == 200
    assert r.get_json() == {"storage": "connected", "provider": "memory"}