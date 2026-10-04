import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from .base import ObjectNotFound, StorageError, StorageService, validate_key

_MISSING_CODES = {"404", "NoSuchKey", "NoSuchBucket", "NotFound"}
MAX_URL_SECONDS = 3600


class S3Storage(StorageService):
    """AWS S3 (production). Also the base class for S3-compatible servers."""

    provider = "s3"

    def __init__(self, bucket, region="us-east-1", access_key=None, secret_key=None,
                 endpoint_url=None, path_style=False):
        self.bucket = bucket
        self.region = region
        # Without explicit keys boto3 uses its default chain (IAM role, env, profile).
        self.client = boto3.client(
            "s3",
            region_name=region,
            aws_access_key_id=access_key or None,
            aws_secret_access_key=secret_key or None,
            endpoint_url=endpoint_url,
            config=Config(
                signature_version="s3v4",
                s3={"addressing_style": "path" if path_style else "auto"},
                retries={"max_attempts": 3, "mode": "standard"},
                connect_timeout=5,
                read_timeout=30,
            ),
        )

    @staticmethod
    def _code(err):
        return str(err.response.get("Error", {}).get("Code", ""))

    def check(self):
        try:
            self.client.head_bucket(Bucket=self.bucket)
            return True
        except (ClientError, BotoCoreError):
            return False

    def ensure_bucket(self):
        # Production rule: the app never creates buckets. It must already exist and be private.
        if not self.check():
            raise StorageError(
                f"Bucket '{self.bucket}' is not reachable. Create it (private) and check credentials."
            )

    def put_object(self, key, data, content_type=None):
        validate_key(key)
        extra = {"ContentType": content_type} if content_type else {}
        try:
            self.client.put_object(Bucket=self.bucket, Key=key, Body=data, **extra)
        except (ClientError, BotoCoreError) as exc:
            raise StorageError("Upload to storage failed.") from exc

    def get_object(self, key):
        validate_key(key)
        try:
            response = self.client.get_object(Bucket=self.bucket, Key=key)
            return response["Body"].read()
        except ClientError as exc:
            if self._code(exc) in _MISSING_CODES:
                raise ObjectNotFound(key) from exc
            raise StorageError("Download from storage failed.") from exc
        except BotoCoreError as exc:
            raise StorageError("Download from storage failed.") from exc

    def delete_object(self, key):
        validate_key(key)
        try:
            self.client.delete_object(Bucket=self.bucket, Key=key)
        except (ClientError, BotoCoreError) as exc:
            raise StorageError("Delete from storage failed.") from exc

    def object_exists(self, key):
        validate_key(key)
        try:
            self.client.head_object(Bucket=self.bucket, Key=key)
            return True
        except ClientError as exc:
            if self._code(exc) in _MISSING_CODES:
                return False
            raise StorageError("Storage lookup failed.") from exc
        except BotoCoreError as exc:
            raise StorageError("Storage lookup failed.") from exc

    def generate_download_url(self, key, expires_in=300, filename=None):
        validate_key(key)
        expires_in = max(1, min(int(expires_in), MAX_URL_SECONDS))
        params = {"Bucket": self.bucket, "Key": key}
        if filename:
            safe = "".join(ch for ch in filename if ch not in '"\r\n\\' and ord(ch) >= 32)
            params["ResponseContentDisposition"] = f'attachment; filename="{safe}"'
        try:
            return self.client.generate_presigned_url(
                "get_object", Params=params, ExpiresIn=expires_in
            )
        except (ClientError, BotoCoreError) as exc:
            raise StorageError("Could not create a download link.") from exc