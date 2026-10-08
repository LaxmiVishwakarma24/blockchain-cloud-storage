from flask import abort, jsonify, render_template, request
from flask_login import current_user, login_required

from ..security.encryption import EncryptionConfigError
from ..storage import StorageError
from . import files_bp, integrity
from .routes import (
    _encryption_response,
    _file_or_404,
    _require_permission,
    _storage_response,
    _version_or_404,
)


def _run_verification(file, version):
    if version is None:
        abort(404)
    try:
        status, calculated, reason = integrity.check_version(version)
    except EncryptionConfigError:
        return _encryption_response()
    except StorageError:
        return _storage_response("The file could not be read for verification.")
    integrity.record_verification(current_user, file, version, status, reason, request.remote_addr)
    return jsonify(
        file_id=file.id,
        version=version.version_number,
        status=status,
        verified=status == integrity.VERIFIED,
        message=integrity.MESSAGES[status],
        expected_sha256=version.sha256,
        calculated_sha256=calculated,
        reason=reason,
        checked_at=version.last_verified_at.isoformat(),
    )


@files_bp.get("/files/<int:file_id>/verify")
@login_required
def verify_page(file_id):
    _require_permission("VERIFY")
    file = _file_or_404(file_id, "VERIFY")
    return render_template("files/verify.html", file_id=file.id, file_name=file.name)


@files_bp.post("/api/files/<int:file_id>/verify")
@login_required
def verify_current(file_id):
    _require_permission("VERIFY")
    file = _file_or_404(file_id, "VERIFY")
    return _run_verification(file, file.current_version)


@files_bp.post("/api/files/<int:file_id>/versions/<int:number>/verify")
@login_required
def verify_version(file_id, number):
    _require_permission("VERIFY")
    file = _file_or_404(file_id, "VERIFY")
    return _run_verification(file, _version_or_404(file, number))