from datetime import timezone

from sqlalchemy import false

from ..extensions import db
from .base import utcnow


class File(db.Model):
    __tablename__ = "files"

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    department_id = db.Column(db.Integer, db.ForeignKey("departments.id"))
    name = db.Column(db.String(255), nullable=False, index=True)
    mime_type = db.Column(db.String(127))
    is_deleted = db.Column(db.Boolean, default=False, nullable=False, index=True)
    deleted_at = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    owner = db.relationship("User", backref="files")
    versions = db.relationship(
        "FileVersion",
        back_populates="file",
        order_by="FileVersion.version_number",
        cascade="all, delete-orphan",
    )

    @property
    def current_version(self):
        return self.versions[-1] if self.versions else None


class FileVersion(db.Model):
    __tablename__ = "file_versions"
    __table_args__ = (db.UniqueConstraint("file_id", "version_number", name="uq_file_version"),)

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("files.id"), nullable=False, index=True)
    version_number = db.Column(db.Integer, nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)  # hash of the ORIGINAL file
    size_bytes = db.Column(db.BigInteger, nullable=False)  # size of the original file
    object_key = db.Column(db.String(512), nullable=False, unique=True)
    is_encrypted = db.Column(db.Boolean, nullable=False, default=False, server_default=false())
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    blockchain_tx_id = db.Column(db.String(128))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)

    file = db.relationship("File", back_populates="versions")
    created_by = db.relationship("User")


class FileShare(db.Model):
    __tablename__ = "file_shares"

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("files.id"), nullable=False, index=True)
    shared_with_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    shared_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    permissions = db.Column(db.JSON, nullable=False, default=list)
    expires_at = db.Column(db.DateTime(timezone=True))
    revoked_at = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)

    file = db.relationship("File", backref="shares")
    shared_with = db.relationship("User", foreign_keys=[shared_with_id])
    shared_by = db.relationship("User", foreign_keys=[shared_by_id])

    @property
    def is_active(self):
        if self.revoked_at is not None:
            return False
        exp = self.expires_at
        if exp is None:
            return True
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return exp > utcnow()