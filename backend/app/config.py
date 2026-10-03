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


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False