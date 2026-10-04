import os

from dotenv import load_dotenv

load_dotenv()

APP_NAME = "Blockchain Cloud Storage"
APP_VERSION = "1.0.0"


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-env")
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg2://postgres:postgres@localhost:5433/blockchain_storage",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("FLASK_ENV") == "production"

    # Uploads: per-file limit, with a little headroom for multipart overhead.
    MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB") or "25")
    MAX_CONTENT_LENGTH = (MAX_UPLOAD_MB + 1) * 1024 * 1024

    # Object storage: "minio" (local development), "s3" (production) or "memory" (tests)
    STORAGE_PROVIDER = (os.getenv("STORAGE_PROVIDER") or "minio").lower()
    SIGNED_URL_EXPIRY_SECONDS = int(os.getenv("SIGNED_URL_EXPIRY_SECONDS") or "300")

    AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "")
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    AWS_REGION = os.getenv("AWS_REGION") or "us-east-1"
    AWS_S3_BUCKET = os.getenv("AWS_S3_BUCKET", "")

    MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT") or "localhost:9000"
    MINIO_USE_SSL = (os.getenv("MINIO_USE_SSL") or "false").lower() == "true"
    MINIO_ROOT_USER = os.getenv("MINIO_ROOT_USER", "")
    MINIO_ROOT_PASSWORD = os.getenv("MINIO_ROOT_PASSWORD", "")
    MINIO_BUCKET = os.getenv("MINIO_BUCKET") or "cloud-storage"


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False
    STORAGE_PROVIDER = "memory"
    MAX_UPLOAD_MB = 1
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024