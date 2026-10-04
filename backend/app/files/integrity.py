from ..audit.services import record_event
from ..extensions import db
from ..models import SecurityAlert
from ..models.base import utcnow
from ..security.encryption import DecryptionError, decrypt_bytes, key_from_config
from ..storage import ObjectNotFound, get_storage
from .hashing import hashes_match, sha256_hex

from flask import current_app

VERIFIED = "VERIFIED"
MISMATCH = "MISMATCH"
MISSING = "MISSING"

MESSAGES = {
    VERIFIED: "File has not changed.",
    MISMATCH: "Possible file modification detected.",
    MISSING: "The stored copy of this file is missing from cloud storage.",
}

ALERT_TYPES = {MISMATCH: "HASH_MISMATCH", MISSING: "OBJECT_MISSING"}


def check_version(version):
    """Re-calculate the SHA-256 of a stored version.

    Returns (status, calculated_sha256, reason). Raises StorageError or
    EncryptionConfigError when the check itself cannot be carried out.
    """
    try:
        data = get_storage().get_object(version.object_key)
    except ObjectNotFound:
        return MISSING, None, "object_missing"
    if version.is_encrypted:
        key = key_from_config(current_app.config)
        try:
            data = decrypt_bytes(key, data, version.object_key.encode("utf-8"))
        except DecryptionError:
            return MISMATCH, None, "authentication_failed"
    calculated = sha256_hex(data)
    if hashes_match(calculated, version.sha256):
        return VERIFIED, calculated, None
    return MISMATCH, calculated, "hash_differs"


def record_verification(user, file, version, status, reason, ip=None):
    """Store the result on the version, audit it and raise an alert when it failed."""
    ok = status == VERIFIED
    user_id = user.id if user is not None else None
    version.last_verified_at = utcnow()
    version.verification_status = status
    record_event(
        "VERIFY",
        "SUCCESS" if ok else "FAILED",
        user_id=user_id,
        file_id=file.id,
        ip=ip,
        details={"version": version.version_number, "result": status, "reason": reason},
    )
    if not ok:
        db.session.add(
            SecurityAlert(
                alert_type=ALERT_TYPES[status],
                severity="CRITICAL",
                message=(
                    f"Verification of file {file.id} version {version.version_number} failed: "
                    f"{MESSAGES[status]}"
                ),
                user_id=user_id,
                file_id=file.id,
            )
        )
    db.session.commit()