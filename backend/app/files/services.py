import contextlib
import uuid

from flask import current_app
from sqlalchemy import func

from ..audit.services import record_event
from ..extensions import db
from ..models import File, FileVersion, SecurityAlert
from ..models.base import utcnow
from ..security.encryption import DecryptionError, decrypt_bytes, encrypt_bytes, key_from_config
from ..storage import StorageError, get_storage
from .hashing import hashes_match, sha256_hex


class IntegrityFailure(Exception):
    """The stored object no longer matches what was uploaded."""


def new_object_key(user_id):
    # The key never contains the user's file name, so it cannot be used for path tricks.
    return f"users/{user_id}/{uuid.uuid4().hex}"


def store_new_file(user, upload, data, ip=None):
    """Hash the data, encrypt it, upload the ciphertext, then record file, version 1 and an audit event."""
    encryption_key = key_from_config(current_app.config)  # fail closed before storage is touched
    storage = get_storage()
    digest = sha256_hex(data)
    object_key = new_object_key(user.id)
    blob = encrypt_bytes(encryption_key, data, object_key.encode("utf-8"))
    storage.put_object(object_key, blob, content_type="application/octet-stream")
    try:
        file = File(owner_id=user.id, name=upload.name, mime_type=upload.mime_type)
        db.session.add(file)
        db.session.flush()
        version = FileVersion(
            file_id=file.id,
            version_number=1,
            sha256=digest,
            size_bytes=len(data),
            object_key=object_key,
            is_encrypted=True,
            created_by_id=user.id,
        )
        db.session.add(version)
        record_event(
            "UPLOAD",
            "SUCCESS",
            user_id=user.id,
            file_id=file.id,
            ip=ip,
            details={"version": 1, "sha256": digest, "size_bytes": len(data)},
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        with contextlib.suppress(StorageError):
            storage.delete_object(object_key)  # do not leave an orphan object behind
        raise
    return file, version


def _create_version(user, file, data, ip, details):
    """Encrypt `data` and store it as the next version of `file`. History is never overwritten."""
    encryption_key = key_from_config(current_app.config)
    storage = get_storage()
    digest = sha256_hex(data)
    object_key = new_object_key(file.owner_id)
    blob = encrypt_bytes(encryption_key, data, object_key.encode("utf-8"))
    storage.put_object(object_key, blob, content_type="application/octet-stream")
    try:
        File.query.filter_by(id=file.id).with_for_update().one()  # serialise concurrent new versions
        latest = (
            db.session.query(func.max(FileVersion.version_number)).filter_by(file_id=file.id).scalar() or 0
        )
        version = FileVersion(
            file_id=file.id,
            version_number=latest + 1,
            sha256=digest,
            size_bytes=len(data),
            object_key=object_key,
            is_encrypted=True,
            created_by_id=user.id,
        )
        db.session.add(version)
        file.updated_at = utcnow()
        record_event(
            "MODIFY",
            "SUCCESS",
            user_id=user.id,
            file_id=file.id,
            ip=ip,
            details={**details, "version": latest + 1, "sha256": digest, "size_bytes": len(data)},
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        with contextlib.suppress(StorageError):
            storage.delete_object(object_key)
        raise
    return version


def add_version(user, file, upload, data, ip=None):
    return _create_version(user, file, data, ip, {"operation": "new_version", "filename": upload.name})


def restore_version(user, file, old_version, ip=None):
    """Copy an old version into a NEW version (after verifying the old one's integrity)."""
    data = read_plaintext(old_version)
    return _create_version(
        user, file, data, ip, {"operation": "restore", "restored_from": old_version.version_number}
    )


def read_plaintext(version):
    """Fetch a version, decrypt it and check it against the stored SHA-256."""
    data = get_storage().get_object(version.object_key)
    if version.is_encrypted:
        key = key_from_config(current_app.config)
        try:
            data = decrypt_bytes(key, data, version.object_key.encode("utf-8"))
        except DecryptionError as exc:
            raise IntegrityFailure("The stored file failed its integrity check.") from exc
    if not hashes_match(sha256_hex(data), version.sha256):
        raise IntegrityFailure("The stored file does not match its recorded SHA-256.")
    return data


def report_integrity_failure(user, file, version, ip=None, action="DOWNLOAD"):
    db.session.add(
        SecurityAlert(
            alert_type="HASH_MISMATCH",
            severity="CRITICAL",
            message=f"Stored object for file {file.id} version {version.version_number} failed its integrity check.",
            user_id=user.id,
            file_id=file.id,
        )
    )
    record_event(
        action,
        "FAILED",
        user_id=user.id,
        file_id=file.id,
        ip=ip,
        details={"version": version.version_number, "reason": "integrity"},
    )
    db.session.commit()