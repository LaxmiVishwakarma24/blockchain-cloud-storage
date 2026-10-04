from datetime import date, datetime, time, timedelta, timezone

from flask import abort, jsonify, render_template, request
from flask_login import current_user, login_required

from ..audit.services import record_event
from ..extensions import db
from ..models import File, FileShare, SecurityAlert, User
from ..models.base import utcnow
from . import access, files_bp
from .routes import _deny, _file_json, _require_permission

# DELETE and SHARE are never handed out through a share.
GRANTABLE = ("VIEW", "DOWNLOAD", "MODIFY", "VERIFY")
MAX_SHARE_DAYS = 365


def _bad(message, status=400):
    return jsonify(error="Share rejected", message=message), status


def _managed_file_or_404(file_id):
    """Load a file only if the current user owns it or is an admin."""
    file = db.session.get(File, file_id)
    if file is None or file.is_deleted:
        abort(404)
    if not access.can_manage(current_user, file):
        db.session.add(
            SecurityAlert(
                alert_type="UNAUTHORIZED_ACCESS",
                severity="MEDIUM",
                message=f"Share management attempted on file {file.id} by someone who is not the owner.",
                user_id=current_user.id,
                file_id=file.id,
            )
        )
        _deny(file.id, needed="SHARE_MANAGE")
        abort(404)
    return file


def _parse_permissions(raw):
    if not isinstance(raw, list) or not raw:
        raise ValueError("Choose at least one permission.")
    chosen = set()
    for item in raw:
        if not isinstance(item, str) or item.upper() not in GRANTABLE:
            raise ValueError("Permissions can only be VIEW, DOWNLOAD, MODIFY or VERIFY.")
        chosen.add(item.upper())
    chosen.add("VIEW")  # access without VIEW makes no sense
    return [name for name in GRANTABLE if name in chosen]


def _parse_expiry(raw):
    if raw in (None, ""):
        return None
    message = "Expiry must be a date like 2026-12-31."
    if not isinstance(raw, str):
        raise ValueError(message)
    text = raw.strip()
    try:
        if len(text) == 10:
            moment = datetime.combine(date.fromisoformat(text), time(23, 59, 59), tzinfo=timezone.utc)
        else:
            moment = datetime.fromisoformat(text)
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError(message) from None
    now = utcnow()
    if moment <= now:
        raise ValueError("The expiry must be in the future.")
    if moment > now + timedelta(days=MAX_SHARE_DAYS):
        raise ValueError(f"The expiry can be at most {MAX_SHARE_DAYS} days ahead.")
    return moment.astimezone(timezone.utc)


def _share_json(share):
    return {
        "id": share.id,
        "file_id": share.file_id,
        "shared_with": share.shared_with.email,
        "username": share.shared_with.username,
        "permissions": share.permissions or [],
        "expires_at": share.expires_at.isoformat() if share.expires_at else None,
        "revoked": share.revoked_at is not None,
        "active": share.is_active,
        "created_at": share.created_at.isoformat() if share.created_at else None,
    }


# ---------------------------------------------------------------- pages

@files_bp.get("/shared")
@login_required
def shared_page():
    return render_template("files/shared.html")


@files_bp.get("/files/<int:file_id>/share")
@login_required
def share_page(file_id):
    _require_permission("SHARE")
    file = _managed_file_or_404(file_id)
    return render_template("files/share.html", file_id=file.id, file_name=file.name)


# ---------------------------------------------------------------- API

@files_bp.post("/api/files/<int:file_id>/shares")
@login_required
def create_share(file_id):
    _require_permission("SHARE")
    file = _managed_file_or_404(file_id)
    payload = request.get_json(silent=True) or {}
    email = payload.get("email")
    if not isinstance(email, str) or not email.strip():
        return _bad("Enter the email address of the person to share with.")
    try:
        permissions = _parse_permissions(payload.get("permissions"))
        expires_at = _parse_expiry(payload.get("expires_at"))
    except ValueError as exc:
        return _bad(str(exc))

    recipient = User.query.filter_by(email=email.strip().lower()).first()
    if recipient is None or not recipient.is_active:
        return _bad("No active user has that email address.", 404)
    if recipient.id == file.owner_id or recipient.id == current_user.id:
        return _bad("The owner already has full access to this file.")

    share = (
        FileShare.query.filter(
            FileShare.file_id == file.id,
            FileShare.shared_with_id == recipient.id,
            FileShare.revoked_at.is_(None),
        )
        .order_by(FileShare.id.desc())
        .first()
    )
    created = share is None
    if created:
        share = FileShare(file_id=file.id, shared_with_id=recipient.id, shared_by_id=current_user.id)
        db.session.add(share)
    share.permissions = permissions
    share.expires_at = expires_at
    record_event(
        "SHARE",
        "SUCCESS",
        user_id=current_user.id,
        file_id=file.id,
        ip=request.remote_addr,
        details={
            "shared_with": recipient.id,
            "permissions": permissions,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "updated": not created,
        },
    )
    db.session.commit()
    return jsonify(_share_json(share)), (201 if created else 200)


@files_bp.get("/api/files/<int:file_id>/shares")
@login_required
def list_shares(file_id):
    _require_permission("SHARE")
    file = _managed_file_or_404(file_id)
    shares = FileShare.query.filter_by(file_id=file.id).order_by(FileShare.id.desc()).all()
    return jsonify(file=_file_json(file), shares=[_share_json(s) for s in shares])


@files_bp.delete("/api/files/<int:file_id>/shares/<int:share_id>")
@login_required
def revoke_share(file_id, share_id):
    _require_permission("SHARE")
    file = _managed_file_or_404(file_id)
    share = db.session.get(FileShare, share_id)
    if share is None or share.file_id != file.id:
        abort(404)
    if share.revoked_at is not None:
        return _bad("That share was already revoked.")
    share.revoked_at = utcnow()
    record_event(
        "UNSHARE",
        "SUCCESS",
        user_id=current_user.id,
        file_id=file.id,
        ip=request.remote_addr,
        details={"shared_with": share.shared_with_id},
    )
    db.session.commit()
    return jsonify(_share_json(share))


@files_bp.get("/api/shared")
@login_required
def shared_with_me():
    _require_permission("VIEW")
    shares = (
        FileShare.query.join(File, File.id == FileShare.file_id)
        .filter(
            FileShare.shared_with_id == current_user.id,
            FileShare.revoked_at.is_(None),
            File.is_deleted.is_(False),
        )
        .order_by(FileShare.id.desc())
        .limit(200)
        .all()
    )
    items = []
    for share in shares:
        if not share.is_active:
            continue  # expired shares disappear by themselves
        entry = _file_json(share.file)
        entry.update(
            share_id=share.id,
            owner=share.file.owner.username,
            permissions=share.permissions or [],
            expires_at=share.expires_at.isoformat() if share.expires_at else None,
        )
        items.append(entry)
    return jsonify(files=items)