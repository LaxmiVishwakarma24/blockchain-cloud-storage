from datetime import timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from ..extensions import db
from .base import utcnow

role_permissions = db.Table(
    "role_permissions",
    db.Column("role_id", db.Integer, db.ForeignKey("roles.id"), primary_key=True),
    db.Column("permission_id", db.Integer, db.ForeignKey("permissions.id"), primary_key=True),
)


class Permission(db.Model):
    __tablename__ = "permissions"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), unique=True, nullable=False)


class Role(db.Model):
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), unique=True, nullable=False)
    permissions = db.relationship("Permission", secondary=role_permissions, lazy="joined")


class Department(db.Model):
    __tablename__ = "departments"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey("departments.id"))
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    failed_login_count = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime(timezone=True))
    last_login_at = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)

    role = db.relationship("Role", backref="users")
    department = db.relationship("Department", backref="users")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_locked(self):
        if self.locked_until is None:
            return False
        until = self.locked_until
        if until.tzinfo is None:
            until = until.replace(tzinfo=timezone.utc)
        return until > utcnow()

    @property
    def role_name(self):
        return self.role.name if self.role else None

    def has_permission(self, name):
        return bool(self.role) and any(p.name == name for p in self.role.permissions)


class LoginAttempt(db.Model):
    __tablename__ = "login_attempts"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    ip_address = db.Column(db.String(45))
    success = db.Column(db.Boolean, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)