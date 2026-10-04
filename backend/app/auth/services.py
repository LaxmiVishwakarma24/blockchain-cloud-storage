import re
from datetime import timedelta

from flask import current_app
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from ..extensions import db
from ..models import LoginAttempt, Role, SecurityAlert, User
from ..models.base import utcnow

MAX_FAILED_ATTEMPTS = 5
LOCK_MINUTES = 15
RESET_TOKEN_MAX_AGE = 3600

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")


def validate_password(password):
    errors = []
    if len(password) < 8:
        errors.append("Password must be at least 8 characters.")
    if len(password) > 128:
        errors.append("Password must be at most 128 characters.")
    if not re.search(r"[a-z]", password):
        errors.append("Password needs a lowercase letter.")
    if not re.search(r"[A-Z]", password):
        errors.append("Password needs an uppercase letter.")
    if not re.search(r"\d", password):
        errors.append("Password needs a digit.")
    return errors


def validate_registration(email, username, password, confirm):
    errors = []
    if not EMAIL_RE.match(email) or len(email) > 255:
        errors.append("Enter a valid email address.")
    if not USERNAME_RE.match(username):
        errors.append("Username must be 3-30 characters: letters, numbers, underscore.")
    errors += validate_password(password)
    if password != confirm:
        errors.append("Passwords do not match.")
    if not errors:
        if User.query.filter_by(email=email).first():
            errors.append("That email is already registered.")
        if User.query.filter(db.func.lower(User.username) == username.lower()).first():
            errors.append("That username is taken.")
    return errors


def register_user(email, username, password):
    role = Role.query.filter_by(name="USER").first()
    if role is None:
        raise RuntimeError("Roles are missing. Run 'flask seed' first.")
    user = User(email=email, username=username, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return user


def _record(email, user, ip, success):
    db.session.add(
        LoginAttempt(
            email=email[:255],
            user_id=user.id if user else None,
            ip_address=ip,
            success=success,
        )
    )


def _alert(alert_type, severity, message, user):
    db.session.add(
        SecurityAlert(alert_type=alert_type, severity=severity, message=message, user_id=user.id)
    )


def authenticate(email, password, ip):
    """Return (user, None) on success or (None, error_message)."""
    email = (email or "").strip().lower()
    password = password or ""
    user = User.query.filter_by(email=email).first()
    generic = "Invalid email or password."

    if user is None:
        _record(email, None, ip, False)
        db.session.commit()
        return None, generic

    if user.is_locked:
        _record(email, user, ip, False)
        db.session.commit()
        return None, "Account temporarily locked after repeated failed attempts. Try again later."

    if len(password) > 128 or not user.check_password(password):
        user.failed_login_count += 1
        if user.failed_login_count >= MAX_FAILED_ATTEMPTS:
            user.locked_until = utcnow() + timedelta(minutes=LOCK_MINUTES)
            user.failed_login_count = 0
            _alert(
                "FAILED_LOGIN",
                "HIGH",
                f"Account locked after {MAX_FAILED_ATTEMPTS} failed login attempts.",
                user,
            )
        _record(email, user, ip, False)
        db.session.commit()
        return None, generic

    if not user.is_active:
        _record(email, user, ip, False)
        _alert("DISABLED_USER_ACCESS", "MEDIUM", "Login attempted on a deactivated account.", user)
        db.session.commit()
        return None, "This account has been deactivated. Contact an administrator."

    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = utcnow()
    _record(email, user, ip, True)
    db.session.commit()
    return user, None


def _serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="password-reset")


def make_reset_token(user):
    # The tail of the current hash ties the token to the current password,
    # so it stops working after the password changes (single use).
    return _serializer().dumps({"uid": user.id, "h": user.password_hash[-12:]})


def verify_reset_token(token):
    try:
        data = _serializer().loads(token, max_age=RESET_TOKEN_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None
    user = db.session.get(User, data["uid"])
    if user is None or user.password_hash[-12:] != data["h"]:
        return None
    return user