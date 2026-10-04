from ..extensions import db
from .base import utcnow


class AuditEvent(db.Model):
    __tablename__ = "audit_events"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    file_id = db.Column(db.Integer, db.ForeignKey("files.id"), index=True)
    action = db.Column(db.String(32), nullable=False, index=True)
    status = db.Column(db.String(16), nullable=False)
    ip_address = db.Column(db.String(45))
    details = db.Column(db.JSON)
    blockchain_tx_id = db.Column(db.String(128))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, index=True)


class BlockchainTransaction(db.Model):
    __tablename__ = "blockchain_transactions"

    id = db.Column(db.Integer, primary_key=True)
    tx_id = db.Column(db.String(128), unique=True, nullable=False)
    block_number = db.Column(db.Integer)
    file_id = db.Column(db.Integer, db.ForeignKey("files.id"), index=True)
    version_number = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    action = db.Column(db.String(32), nullable=False)
    sha256 = db.Column(db.String(64))
    status = db.Column(db.String(16), nullable=False, default="COMMITTED")
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)


class SecurityAlert(db.Model):
    __tablename__ = "security_alerts"

    id = db.Column(db.Integer, primary_key=True)
    alert_type = db.Column(db.String(48), nullable=False, index=True)
    severity = db.Column(db.String(16), nullable=False, default="MEDIUM")
    message = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    file_id = db.Column(db.Integer, db.ForeignKey("files.id"))
    resolved = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)


class Notification(db.Model):
    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    title = db.Column(db.String(120), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)