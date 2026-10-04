from botocore.exceptions import BotoCoreError, ClientError

from .base import StorageError
from .s3 import S3Storage


class MinIOStorage(S3Storage):
    """Local-development storage. Same S3 API, different endpoint."""

    provider = "minio"

    def __init__(self, endpoint, bucket, access_key, secret_key, use_ssl=False, region="us-east-1"):
        host = endpoint.split("://")[-1].strip("/")
        scheme = "https" if use_ssl else "http"
        super().__init__(
            bucket=bucket,
            region=region,
            access_key=access_key,
            secret_key=secret_key,
            endpoint_url=f"{scheme}://{host}",
            path_style=True,
        )

    def ensure_bucket(self):
        # Development convenience: create the bucket (private by default) if it is missing.
        if self.check():
            return
        try:
            self.client.create_bucket(Bucket=self.bucket)
        except (ClientError, BotoCoreError) as exc:
            raise StorageError("Could not create the storage bucket.") from exc