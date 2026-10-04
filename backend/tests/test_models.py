from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import File, FileShare, FileVersion, Role, User
from app.seed import seed_roles_and_permissions


def make_user(email="alice@example.com"):
    role = Role.query.filter_by(name="USER").first()
    user = User(email=email, username=email.split("@")[0], password_hash="x", role=role)
    db.session.add(user)
    db.session.commit()
    return user


def make_version(file, number, user):
    return FileVersion(
        file=file, version_number=number, sha256="a" * 64, size_bytes=10,
        object_key=f"files/{file.id}/v{number}", created_by=user,
    )


def test_seed_creates_roles_and_permissions(app):
    seed_roles_and_permissions()
    assert {r.name for r in Role.query.all()} == {"ADMIN", "MANAGER", "USER"}
    assert len(Role.query.filter_by(name="ADMIN").first().permissions) == 7
    assert len(Role.query.filter_by(name="USER").first().permissions) == 4


def test_seed_is_idempotent(app):
    seed_roles_and_permissions()
    seed_roles_and_permissions()
    assert Role.query.count() == 3


def test_file_versions_keep_history(app):
    seed_roles_and_permissions()
    user = make_user()
    f = File(owner=user, name="report.pdf")
    db.session.add(f)
    db.session.commit()
    db.session.add_all([make_version(f, 1, user), make_version(f, 2, user)])
    db.session.commit()
    assert [v.version_number for v in f.versions] == [1, 2]
    assert f.current_version.version_number == 2


def test_duplicate_version_number_is_rejected(app):
    seed_roles_and_permissions()
    user = make_user()
    f = File(owner=user, name="report.pdf")
    db.session.add(f)
    db.session.commit()
    db.session.add(make_version(f, 1, user))
    db.session.commit()
    db.session.add(FileVersion(
        file=f, version_number=1, sha256="b" * 64, size_bytes=5,
        object_key="files/other", created_by=user,
    ))
    with pytest.raises(IntegrityError):
        db.session.commit()


def test_expired_share_is_not_active(app):
    seed_roles_and_permissions()
    owner, guest = make_user("owner@example.com"), make_user("guest@example.com")
    f = File(owner=owner, name="doc.pdf")
    db.session.add(f)
    db.session.commit()
    past = datetime.now(timezone.utc) - timedelta(days=1)
    future = datetime.now(timezone.utc) + timedelta(days=1)
    expired = FileShare(file=f, shared_with=guest, shared_by=owner, permissions=["VIEW"], expires_at=past)
    valid = FileShare(file=f, shared_with=guest, shared_by=owner, permissions=["VIEW"], expires_at=future)
    db.session.add_all([expired, valid])
    db.session.commit()
    assert expired.is_active is False
    assert valid.is_active is True