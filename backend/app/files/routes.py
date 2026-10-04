import io
from datetime import datetime, timedelta, timezone

from flask import abort, current_app, jsonify, render_template, request, send_file
from flask_login import current_user, login_required

from ..audit.services import record_event
from ..extensions import db
from ..models import File, SecurityAlert
from ..models.base import utcnow
from ..security.encryption import EncryptionConfigError
from ..storage import ObjectNotFound, StorageError
from . import access, files_bp, services
from .validation import (
    ALLOWED_TYPES,
    UploadValidationError,
    clean_filename,
    file_extension,
    validate_upload,
)


# ---------------------------------------------------------------- helpers

def _deny(file_id=None, **details):
    record_event(
        "ACCESS_DENIED",
        "DENIED",
        user_id=current_user.id,
        file_id=file_id,
        ip=request.remote_addr,
        details=details or None,
    )
    db.session.commit()


def _require_permission(name):
    """Enforce the role's permission on the server, whatever the UI shows."""
    if not current_user.has_permission(name):
        _deny(needed=name)
        abort(403)


def _file_or_404(file_id, permission, include_deleted=False):
    """Load a file the current user may use for `permission`; otherwise answer 404."""
    file = db.session.get(File, file_id)
    if file is None or (file.is_deleted and not include_deleted):
        abort(404)
    if not access.can(current_user, file, permission):
        alert_type = access.denial_alert_type(current_user, file, permission)
        db.session.add(
            SecurityAlert(
                alert_type=alert_type,
                severity="HIGH" if permission == "DELETE" else "MEDIUM",
                message=f"{permission} attempted on file {file.id} without permission.",
                user_id=current_user.id,
                file_id=file.id,
            )
        )
        _deny(file.id, needed=permission)
        abort(404)  # same answer as "does not exist", so IDs cannot be probed
    return file


def _version_or_404(file, number):
    for version in file.versions:
        if version.version_number == number:
            return version
    abort(404)


def _file_json(file):
    version = file.current_version
    return {
        "id": file.id,
        "name": file.name,
        "mime_type": file.mime_type,
        "version": version.version_number if version else None,
        "size_bytes": version.size_bytes if version else None,
        "sha256": version.sha256 if version else None,
        "encrypted": version.is_encrypted if version else None,
        "verification": version.verification_status if version else None,
        "verified_at": version.last_verified_at.isoformat() if version and version.last_verified_at else None,
        "deleted": file.is_deleted,
        "created_at": file.created_at.isoformat() if file.created_at else None,
        "updated_at": file.updated_at.isoformat() if file.updated_at else None,
    }


def _version_json(version):
    return {
        "id": version.id,
        "version": version.version_number,
        "sha256": version.sha256,
        "size_bytes": version.size_bytes,
        "encrypted": version.is_encrypted,
        "verification": version.verification_status,
        "verified_at": version.last_verified_at.isoformat() if version.last_verified_at else None,
        "created_by": version.created_by.username if version.created_by else None,
        "created_at": version.created_at.isoformat() if version.created_at else None,
    }


def _storage_response(message="The file could not be stored."):
    current_app.logger.exception("Storage failure")
    return jsonify(error="Storage unavailable", message=message), 503


def _encryption_response():
    current_app.logger.error("Encryption key is missing or invalid")
    return jsonify(error="Encryption unavailable", message="Encryption is not configured on the server."), 503


def _integrity_response():
    return (
        jsonify(
            error="Integrity check failed",
            message="The stored file failed its integrity check and was not delivered.",
        ),
        409,
    )


def _parse_day(value, end_of_day=False):
    if not value:
        return None
    try:
        day = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        abort(400, description="Dates must look like 2026-10-31.")
    return day + timedelta(days=1) if end_of_day else day


def _deliver(file, version):
    try:
        data = services.read_plaintext(version)
    except ObjectNotFound:
        abort(404)
    except services.IntegrityFailure:
        services.report_integrity_failure(current_user, file, version, request.remote_addr)
        return _integrity_response()
    except EncryptionConfigError:
        return _encryption_response()
    except StorageError:
        return _storage_response("The file could not be read.")

    record_event(
        "DOWNLOAD",
        "SUCCESS",
        user_id=current_user.id,
        file_id=file.id,
        ip=request.remote_addr,
        details={"version": version.version_number},
    )
    db.session.commit()
    return send_file(
        io.BytesIO(data),
        mimetype=file.mime_type or "application/octet-stream",
        as_attachment=True,
        download_name=file.name,
    )


# ---------------------------------------------------------------- pages

@files_bp.get("/files")
@login_required
def files_page():
    return render_template("files/index.html")


@files_bp.get("/files/upload")
@login_required
def upload_page():
    return render_template("files/upload.html", max_mb=current_app.config["MAX_UPLOAD_MB"])


@files_bp.get("/files/<int:file_id>/versions")
@login_required
def versions_page(file_id):
    _require_permission("VIEW")
    file = _file_or_404(file_id, "VIEW")
    return render_template("files/versions.html", file_id=file.id, file_name=file.name)


# ---------------------------------------------------------------- upload

@files_bp.post("/api/files/upload")
@login_required
def upload():
    _require_permission("UPLOAD")
    uploaded = request.files.get("file")
    if uploaded is None:
        return jsonify(error="Bad Request", message="Send the file in the 'file' form field."), 400

    max_bytes = current_app.config["MAX_UPLOAD_MB"] * 1024 * 1024
    data = uploaded.stream.read(max_bytes + 1)
    try:
        checked = validate_upload(uploaded.filename, uploaded.mimetype, data, max_bytes)
    except UploadValidationError as exc:
        record_event(
            "UPLOAD",
            "REJECTED",
            user_id=current_user.id,
            ip=request.remote_addr,
            details={"reason": str(exc)},
        )
        db.session.commit()
        return jsonify(error="Upload rejected", message=str(exc)), exc.status_code

    try:
        file, _ = services.store_new_file(current_user, checked, data, ip=request.remote_addr)
    except EncryptionConfigError:
        return _encryption_response()
    except StorageError:
        return _storage_response()

    current_app.logger.info(
        "UPLOAD", extra={"user": current_user.id, "action": "UPLOAD", "file": file.id, "status": "SUCCESS"}
    )
    return jsonify(_file_json(file)), 201


# ---------------------------------------------------------------- list, detail, rename, delete

@files_bp.get("/api/files")
@login_required
def list_files():
    _require_permission("VIEW")
    args = request.args
    in_trash = args.get("view") == "trash"
    query = File.query.filter_by(owner_id=current_user.id, is_deleted=in_trash)

    text = (args.get("q") or "").strip()[:100]
    if text:
        escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        query = query.filter(File.name.ilike(f"%{escaped}%", escape="\\"))

    extension = (args.get("type") or "").lower().lstrip(".")
    if extension:
        if extension not in ALLOWED_TYPES:
            abort(400, description="Unknown file type filter.")
        query = query.filter(File.name.ilike(f"%.{extension}"))

    start = _parse_day(args.get("from"))
    end = _parse_day(args.get("to"), end_of_day=True)
    if start:
        query = query.filter(File.created_at >= start)
    if end:
        query = query.filter(File.created_at < end)

    columns = {"name": File.name, "created": File.created_at, "updated": File.updated_at}
    column = columns.get(args.get("sort") or "created", File.created_at)
    column = column.asc() if args.get("order") == "asc" else column.desc()

    page = max(args.get("page", 1, type=int), 1)
    per_page = min(max(args.get("per_page", 20, type=int), 1), 100)
    total = query.count()
    files = query.order_by(column, File.id.desc()).offset((page - 1) * per_page).limit(per_page).all()
    return jsonify(
        files=[_file_json(f) for f in files], page=page, per_page=per_page, total=total
    )


@files_bp.get("/api/files/<int:file_id>")
@login_required
def file_detail(file_id):
    _require_permission("VIEW")
    return jsonify(_file_json(_file_or_404(file_id, "VIEW")))


@files_bp.patch("/api/files/<int:file_id>")
@login_required
def rename_file(file_id):
    _require_permission("MODIFY")
    file = _file_or_404(file_id, "MODIFY")
    payload = request.get_json(silent=True) or {}
    name = payload.get("name")
    if not isinstance(name, str):
        return jsonify(error="Rename rejected", message="Send the new name as JSON: {\"name\": \"...\"}."), 400
    try:
        new_name = clean_filename(name)
        new_extension = file_extension(new_name)
    except UploadValidationError as exc:
        return jsonify(error="Rename rejected", message=str(exc)), exc.status_code
    if new_extension != file_extension(file.name):
        return jsonify(error="Rename rejected", message="The file extension cannot be changed."), 400

    old_name = file.name
    file.name = new_name
    file.updated_at = utcnow()
    record_event(
        "MODIFY",
        "SUCCESS",
        user_id=current_user.id,
        file_id=file.id,
        ip=request.remote_addr,
        details={"operation": "rename", "from": old_name, "to": new_name},
    )
    db.session.commit()
    return jsonify(_file_json(file))


@files_bp.delete("/api/files/<int:file_id>")
@login_required
def delete_file(file_id):
    _require_permission("DELETE")
    file = _file_or_404(file_id, "DELETE")
    file.is_deleted = True
    file.deleted_at = utcnow()
    record_event(
        "DELETE", "SUCCESS", user_id=current_user.id, file_id=file.id, ip=request.remote_addr
    )
    db.session.commit()
    return jsonify(_file_json(file))


@files_bp.post("/api/files/<int:file_id>/restore")
@login_required
def restore_file(file_id):
    _require_permission("DELETE")
    file = _file_or_404(file_id, "DELETE", include_deleted=True)
    if not file.is_deleted:
        return jsonify(error="Bad Request", message="That file is not in the trash."), 400
    file.is_deleted = False
    file.deleted_at = None
    file.updated_at = utcnow()
    record_event(
        "MODIFY",
        "SUCCESS",
        user_id=current_user.id,
        file_id=file.id,
        ip=request.remote_addr,
        details={"operation": "undelete"},
    )
    db.session.commit()
    return jsonify(_file_json(file))


# ---------------------------------------------------------------- download and versions

@files_bp.get("/api/files/<int:file_id>/download")
@login_required
def download(file_id):
    _require_permission("DOWNLOAD")
    file = _file_or_404(file_id, "DOWNLOAD")
    return _deliver(file, file.current_version)


@files_bp.get("/api/files/<int:file_id>/versions")
@login_required
def list_versions(file_id):
    _require_permission("VIEW")
    file = _file_or_404(file_id, "VIEW")
    ordered = sorted(file.versions, key=lambda v: v.version_number, reverse=True)
    return jsonify(file=_file_json(file), versions=[_version_json(v) for v in ordered])


@files_bp.post("/api/files/<int:file_id>/versions")
@login_required
def add_version(file_id):
    _require_permission("UPLOAD")
    file = _file_or_404(file_id, "MODIFY")
    uploaded = request.files.get("file")
    if uploaded is None:
        return jsonify(error="Bad Request", message="Send the file in the 'file' form field."), 400

    max_bytes = current_app.config["MAX_UPLOAD_MB"] * 1024 * 1024
    data = uploaded.stream.read(max_bytes + 1)
    try:
        checked = validate_upload(uploaded.filename, uploaded.mimetype, data, max_bytes)
    except UploadValidationError as exc:
        record_event(
            "MODIFY",
            "REJECTED",
            user_id=current_user.id,
            file_id=file.id,
            ip=request.remote_addr,
            details={"reason": str(exc)},
        )
        db.session.commit()
        return jsonify(error="Upload rejected", message=str(exc)), exc.status_code
    if checked.mime_type != file.mime_type:
        return (
            jsonify(error="Upload rejected", message="A new version must be the same type of file."),
            415,
        )

    try:
        version = services.add_version(current_user, file, checked, data, ip=request.remote_addr)
    except EncryptionConfigError:
        return _encryption_response()
    except StorageError:
        return _storage_response()
    return jsonify(_version_json(version)), 201


@files_bp.get("/api/files/<int:file_id>/versions/<int:number>/download")
@login_required
def download_version(file_id, number):
    _require_permission("DOWNLOAD")
    file = _file_or_404(file_id, "DOWNLOAD")
    return _deliver(file, _version_or_404(file, number))


@files_bp.post("/api/files/<int:file_id>/versions/<int:number>/restore")
@login_required
def restore_old_version(file_id, number):
    _require_permission("MODIFY")
    file = _file_or_404(file_id, "MODIFY")
    old = _version_or_404(file, number)
    try:
        version = services.restore_version(current_user, file, old, ip=request.remote_addr)
    except ObjectNotFound:
        abort(404)
    except services.IntegrityFailure:
        services.report_integrity_failure(current_user, file, old, request.remote_addr, action="MODIFY")
        return _integrity_response()
    except EncryptionConfigError:
        return _encryption_response()
    except StorageError:
        return _storage_response()
    return jsonify(_version_json(version)), 201