import contextlib
import uuid

from ..audit.services import record_event
from ..extensions import db
from ..models import File, FileVersion
from ..storage import StorageError, get_storage
from .hashing import sha256_hex


def new_object_key(user_id):
    # The key never contains the user's file name, so it cannot be used for path tricks.
    return f"users/{user_id}/{uuid.uuid4().hex}"


def store_new_file(user, upload, data, ip=None):
    """Hash the data, upload it, then record the file, version 1 and an audit event."""
    storage = get_storage()
    digest = sha256_hex(data)
    key = new_object_key(user.id)
    storage.put_object(key, data, content_type=upload.mime_type)
    try:
        file = File(owner_id=user.id, name=upload.name, mime_type=upload.mime_type)
        db.session.add(file)
        db.session.flush()
        version = FileVersion(
            file_id=file.id,
            version_number=1,
            sha256=digest,
            size_bytes=len(data),
            object_key=key,
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
            storage.delete_object(key)  # do not leave an orphan object behind
        raise
    return file, version