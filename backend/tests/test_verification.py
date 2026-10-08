import io

import pytest

from app.extensions import db
from app.files.hashing import sha256_hex
from app.models import AuditEvent, File, FileShare, FileVersion, Role, SecurityAlert, User
from app.seed import seed_roles_and_permissions
from app.storage import StorageError, get_storage

PASSWORD = "Str0ngPass1"
PDF = b"%PDF-1.4\n" + b"verifiable document\n"
PDF_B = b"%PDF-1.4\n" + b"second version\n"


@pytest.fixture(autouse=True)
def seeded(app):
    seed_roles_and_permissions()


def make_user(email):
    user = User(
        email=email,
        username=email.split("@")[0],
        role=Role.query.filter_by(name="USER").first(),
    )
    user.set_password(PASSWORD)
    db.session.add(user)
    db.session.commit()
    return user


def login(client, email):
    return client.post("/login", data={"email": email, "password": PASSWORD})


def switch(client, email):
    client.post("/logout")
    login(client, email)


def upload(client, name="report.pdf", data=PDF):
    return client.post(
        "/api/files/upload",
        data={"file": (io.BytesIO(data), name, "application/pdf")},
        content_type="multipart/form-data",
    )


def setup(client):
    alice = make_user("alice@example.com")
    bob = make_user("bob@example.com")
    login(client, "alice@example.com")
    file_id = upload(client).get_json()["id"]
    return file_id, alice, bob


def verify(client, file_id, version=None):
    if version is None:
        return client.post(f"/api/files/{file_id}/verify")
    return client.post(f"/api/files/{file_id}/versions/{version}/verify")


def flip_last_byte(version):
    storage = get_storage()
    blob = bytearray(storage.get_object(version.object_key))
    blob[-1] ^= 0x01
    storage.put_object(version.object_key, bytes(blob))


def test_verification_requires_login(client):
    assert client.post("/api/files/1/verify").status_code == 401


def test_untouched_file_verifies(client):
    file_id, _, _ = setup(client)
    r = verify(client, file_id)
    assert r.status_code == 200
    body = r.get_json()
    assert body["status"] == "VERIFIED"
    assert body["verified"] is True
    assert body["message"] == "File has not changed."
    assert body["expected_sha256"] == body["calculated_sha256"] == sha256_hex(PDF)
    version = FileVersion.query.one()
    assert version.verification_status == "VERIFIED"
    assert version.last_verified_at is not None
    event = AuditEvent.query.filter_by(action="VERIFY").one()
    assert event.status == "SUCCESS"
    assert SecurityAlert.query.count() == 0


def test_modified_cloud_object_is_detected(client):
    file_id, _, _ = setup(client)
    flip_last_byte(FileVersion.query.one())
    r = verify(client, file_id)
    assert r.status_code == 200
    body = r.get_json()
    assert body["status"] == "MISMATCH"
    assert body["verified"] is False
    assert body["message"] == "Possible file modification detected."
    assert body["reason"] == "authentication_failed"
    assert body["calculated_sha256"] is None
    assert FileVersion.query.one().verification_status == "MISMATCH"
    assert SecurityAlert.query.filter_by(alert_type="HASH_MISMATCH", severity="CRITICAL").count() == 1
    assert AuditEvent.query.filter_by(action="VERIFY", status="FAILED").count() == 1


def test_changed_database_hash_is_detected(client):
    file_id, _, _ = setup(client)
    version = FileVersion.query.one()
    version.sha256 = "0" * 64
    db.session.commit()
    body = verify(client, file_id).get_json()
    assert body["status"] == "MISMATCH"
    assert body["reason"] == "hash_differs"
    assert body["calculated_sha256"] == sha256_hex(PDF)


def test_missing_cloud_object_is_reported(client):
    file_id, _, _ = setup(client)
    get_storage().delete_object(FileVersion.query.one().object_key)
    body = verify(client, file_id).get_json()
    assert body["status"] == "MISSING"
    assert body["reason"] == "object_missing"
    assert SecurityAlert.query.filter_by(alert_type="OBJECT_MISSING").count() == 1


def test_legacy_unencrypted_versions_are_verified_too(client):
    _, alice, _ = setup(client)
    legacy = File(owner=alice, name="old.txt", mime_type="text/plain")
    db.session.add(legacy)
    db.session.commit()
    get_storage().put_object("users/1/legacy", b"old data")
    db.session.add(
        FileVersion(
            file_id=legacy.id,
            version_number=1,
            sha256=sha256_hex(b"old data"),
            size_bytes=8,
            object_key="users/1/legacy",
            created_by_id=alice.id,
            is_encrypted=False,
        )
    )
    db.session.commit()
    assert verify(client, legacy.id).get_json()["status"] == "VERIFIED"
    get_storage().put_object("users/1/legacy", b"changed!")
    body = verify(client, legacy.id).get_json()
    assert body["status"] == "MISMATCH"
    assert body["reason"] == "hash_differs"


def test_other_users_cannot_verify_a_file(client):
    file_id, _, _ = setup(client)
    switch(client, "bob@example.com")
    assert verify(client, file_id).status_code == 404
    assert AuditEvent.query.filter_by(action="VERIFY").count() == 0
    assert SecurityAlert.query.filter_by(alert_type="UNAUTHORIZED_ACCESS").count() == 1


def test_share_must_include_verify_permission(client):
    file_id, alice, bob = setup(client)
    db.session.add(
        FileShare(
            file_id=file_id, shared_with_id=bob.id, shared_by_id=alice.id,
            permissions=["VIEW", "DOWNLOAD"],
        )
    )
    db.session.commit()
    switch(client, "bob@example.com")
    assert verify(client, file_id).status_code == 404
    FileShare.query.one().permissions = ["VIEW", "VERIFY"]
    db.session.commit()
    assert verify(client, file_id).get_json()["status"] == "VERIFIED"


def test_specific_versions_can_be_verified(client):
    file_id, _, _ = setup(client)
    r = client.post(
        f"/api/files/{file_id}/versions",
        data={"file": (io.BytesIO(PDF_B), "report.pdf", "application/pdf")},
        content_type="multipart/form-data",
    )
    assert r.status_code == 201
    assert verify(client, file_id, 1).get_json()["version"] == 1
    assert verify(client, file_id).get_json()["version"] == 2
    assert verify(client, file_id, 99).status_code == 404


def test_missing_encryption_key_returns_503(client, app):
    file_id, _, _ = setup(client)
    app.config["ENCRYPTION_KEY"] = ""
    assert verify(client, file_id).status_code == 503
    assert FileVersion.query.one().verification_status is None


def test_storage_failure_returns_503(client, monkeypatch):
    file_id, _, _ = setup(client)

    def boom(*args, **kwargs):
        raise StorageError("down")

    monkeypatch.setattr(get_storage(), "get_object", boom)
    assert verify(client, file_id).status_code == 503


def test_verify_page_access(client):
    assert client.get("/files/1/verify").status_code == 302
    file_id, _, _ = setup(client)
    r = client.get(f"/files/{file_id}/verify")
    assert r.status_code == 200
    assert b"report.pdf" in r.data
    switch(client, "bob@example.com")
    assert client.get(f"/files/{file_id}/verify").status_code == 404


def test_verification_result_appears_in_file_details(client):
    file_id, _, _ = setup(client)
    assert client.get(f"/api/files/{file_id}").get_json()["verification"] is None
    verify(client, file_id)
    detail = client.get(f"/api/files/{file_id}").get_json()
    assert detail["verification"] == "VERIFIED"
    assert detail["verified_at"] is not None