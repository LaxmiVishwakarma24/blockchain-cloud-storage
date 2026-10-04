import io

from flask import abort, current_app, jsonify, render_template, request, send_file
from flask_login import current_user, login_required

from ..audit.services import record_event
from ..extensions import db
from ..models import File
from ..storage import ObjectNotFound, StorageError, get_storage
from . import files_bp, services
from .validation import UploadValidationError, validate_upload


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


def _file_or_404(file_id):
    file = db.session.get(File, file_id)
    if file is None or file.is_deleted:
        abort(404)
    if file.owner_id != current_user.id and current_user.role_name != "ADMIN":
        _deny(file_id=file.id)
        abort(404)  # same answer as "does not exist", so IDs cannot be probed
    return file


def _file_json(file):
    version = file.current_version
    return {
        "id": file.id,
        "name": file.name,
        "mime_type": file.mime_type,
        "version": version.version_number if version else None,
        "size_bytes": version.size_bytes if version else None,
        "sha256": version.sha256 if version else None,
        "created_at": file.created_at.isoformat() if file.created_at else None,
    }


@files_bp.get("/files/upload")
@login_required
def upload_page():
    return render_template("files/upload.html", max_mb=current_app.config["MAX_UPLOAD_MB"])


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
    except StorageError:
        current_app.logger.exception("Storage failure during upload")
        return jsonify(error="Storage unavailable", message="The file could not be stored."), 503

    current_app.logger.info(
        "UPLOAD", extra={"user": current_user.id, "action": "UPLOAD", "file": file.id, "status": "SUCCESS"}
    )
    return jsonify(_file_json(file)), 201


@files_bp.get("/api/files")
@login_required
def list_files():
    _require_permission("VIEW")
    files = (
        File.query.filter_by(owner_id=current_user.id, is_deleted=False)
        .order_by(File.created_at.desc())
        .all()
    )
    return jsonify(files=[_file_json(f) for f in files])


@files_bp.get("/api/files/<int:file_id>")
@login_required
def file_detail(file_id):
    _require_permission("VIEW")
    return jsonify(_file_json(_file_or_404(file_id)))


@files_bp.get("/api/files/<int:file_id>/download")
@login_required
def download(file_id):
    _require_permission("DOWNLOAD")
    file = _file_or_404(file_id)
    version = file.current_version
    try:
        data = get_storage().get_object(version.object_key)
    except ObjectNotFound:
        abort(404)
    except StorageError:
        current_app.logger.exception("Storage failure during download")
        return jsonify(error="Storage unavailable", message="The file could not be read."), 503

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