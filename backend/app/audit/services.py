from ..extensions import db
from ..models import AuditEvent


def record_event(action, status, user_id=None, file_id=None, ip=None, details=None):
    """Queue an audit event. The caller commits it together with its own changes."""
    db.session.add(
        AuditEvent(
            user_id=user_id,
            file_id=file_id,
            action=action,
            status=status,
            ip_address=ip,
            details=details,
        )
    )