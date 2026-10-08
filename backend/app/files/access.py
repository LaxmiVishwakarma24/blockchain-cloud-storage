from ..models import FileShare


def share_permissions(user, file):
    """Permissions granted to `user` by active (not revoked, not expired) shares."""
    granted = set()
    for share in FileShare.query.filter_by(file_id=file.id, shared_with_id=user.id).all():
        if share.is_active:
            granted.update(share.permissions or [])
    return granted


def can(user, file, permission):
    """File-level check: admins and owners can do everything, others only what a share grants."""
    if user.role_name == "ADMIN" or file.owner_id == user.id:
        return True
    return permission in share_permissions(user, file)


def can_manage(user, file):
    """Only the owner or an admin may share, list or revoke shares."""
    return user.role_name == "ADMIN" or file.owner_id == user.id


def has_expired_share(user, file):
    """True if the user was given access that has since run out (revoked shares do not count)."""
    shares = FileShare.query.filter(
        FileShare.file_id == file.id,
        FileShare.shared_with_id == user.id,
        FileShare.revoked_at.is_(None),
    ).all()
    return bool(shares) and not any(share.is_active for share in shares)


def denial_alert_type(user, file, permission):
    if permission == "DELETE":
        return "UNAUTHORIZED_DELETE"
    if has_expired_share(user, file):
        return "EXPIRED_ACCESS"
    return "UNAUTHORIZED_ACCESS"