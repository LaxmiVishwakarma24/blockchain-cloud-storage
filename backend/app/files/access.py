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