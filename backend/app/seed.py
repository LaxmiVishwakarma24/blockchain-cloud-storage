from .extensions import db
from .models import Permission, Role

PERMISSIONS = ["VIEW", "DOWNLOAD", "UPLOAD", "MODIFY", "DELETE", "SHARE", "VERIFY"]

ROLE_PERMISSIONS = {
    "ADMIN": PERMISSIONS,
    "MANAGER": ["VIEW", "DOWNLOAD", "UPLOAD", "MODIFY", "SHARE", "VERIFY"],
    "USER": ["VIEW", "DOWNLOAD", "UPLOAD", "MODIFY", "DELETE", "VERIFY"],
}


def seed_roles_and_permissions():
    perms = {}
    for name in PERMISSIONS:
        perm = Permission.query.filter_by(name=name).first() or Permission(name=name)
        db.session.add(perm)
        perms[name] = perm
    for role_name, names in ROLE_PERMISSIONS.items():
        role = Role.query.filter_by(name=role_name).first() or Role(name=role_name)
        role.permissions = [perms[n] for n in names]
        db.session.add(role)
    db.session.commit()