from flask import jsonify
from sqlalchemy import text

from ..config import APP_NAME, APP_VERSION
from ..extensions import db
from . import health_bp


@health_bp.get("/api/health")
def health():
    return jsonify(status="healthy", application=APP_NAME, version=APP_VERSION)


@health_bp.get("/api/health/db")
def health_db():
    try:
        db.session.execute(text("SELECT 1"))
        return jsonify(database="connected")
    except Exception:
        return jsonify(database="unavailable"), 503