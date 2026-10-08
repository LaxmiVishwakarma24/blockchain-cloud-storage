import io

import pytest

from app.extensions import db
from app.files.hashing import sha256_hex
from app.models import AuditEvent, File, FileVersion, Role, SecurityAlert, User
from app.seed import seed_roles_and_permissions
from app.storage import get_storage

PASSWORD = "Str0ngPass1"
PDF = b"%PDF-1.4\n" + b"confidential report body\n"
OTHER = b"%PDF-1.4\n" + b"another document\n"


@pytest.fixture(autouse=True)
def seeded(app):
    seed_roles_and_permissions()


def make_user(email="alice@example.com"):
    user = User(
        email=email,
        username=email.split("@")[0],
        role=Role.query.filter_by(name="USER").first(),
    )
    user.set_password(PASSWORD)
    db.session.add(user)
    db.session.commit()
    return user


def login(client, email="alice@example.com"):
    return client.post("/login", data={"email": email, "password": PASSWORD})


def upload(client, name="report.pdf", data=PDF):
    return client.post(
        "/api/files/upload",
        data={"file": (io.BytesIO(data), name, "application/pdf")},
        content_type="multipart/form-data",
    )


def test_storage_holds_ciphertext_and_download_decrypts(client):
    make_user()
    login(client)
    body = upload(client).get_json()
    version = FileVersion.query.one()
    stored = get_storage().get_object(version.object_key)
    assert version.is_encrypted is True
    assert b"confidential report body" not in stored
    assert stored[0] == 1
    assert len(stored) == len(PDF) + 1 + 12 + 16
    assert version.sha256 == sha256_hex(PDF)  # fingerprint of the original file
    r = client.get(f"/api/files/{body['id']}/download")
    assert r.status_code == 200
    assert r.data == PDF


def test_same_file_uploaded_twice_gives_different_ciphertext(client):
    make_user()
    login(client)
    upload(client)
    upload(client)
    first, second = FileVersion.query.order_by(FileVersion.id).all()
    assert first.sha256 == second.sha256
    storage = get_storage()
    assert storage.get_object(first.object_key) != storage.get_object(second.object_key)


def test_tampered_object_is_detected_and_alerts(client):
    make_user()
    login(client)
    file_id = upload(client).get_json()["id"]
    version = FileVersion.query.one()
    storage = get_storage()
    blob = bytearray(storage.get_object(version.object_key))
    blob[-1] ^= 0x01
    storage.put_object(version.object_key, bytes(blob))
    r = client.get(f"/api/files/{file_id}/download")
    assert r.status_code == 409
    assert r.get_json()["error"] == "Integrity check failed"
    assert SecurityAlert.query.filter_by(alert_type="HASH_MISMATCH").count() == 1
    assert AuditEvent.query.filter_by(action="DOWNLOAD", status="FAILED").count() == 1


def test_swapping_two_stored_objects_is_detected(client):
    make_user()
    login(client)
    first_id = upload(client, "a.pdf", PDF).get_json()["id"]
    upload(client, "b.pdf", OTHER)
    first, second = FileVersion.query.order_by(FileVersion.id).all()
    storage = get_storage()
    storage.put_object(first.object_key, storage.get_object(second.object_key))
    assert client.get(f"/api/files/{first_id}/download").status_code == 409


def test_upload_without_encryption_key_fails_closed(client, app):
    make_user()
    login(client)
    app.config["ENCRYPTION_KEY"] = ""
    r = upload(client)
    assert r.status_code == 503
    assert File.query.count() == 0
    assert FileVersion.query.count() == 0
    assert get_storage()._objects == {}


def test_legacy_unencrypted_versions_still_download(client):
    user = make_user()
    login(client)
    legacy = File(owner=user, name="old.txt", mime_type="text/plain")
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
            created_by_id=user.id,
            is_encrypted=False,
        )
    )
    db.session.commit()
    r = client.get(f"/api/files/{legacy.id}/download")
    assert r.status_code == 200
    assert r.data == b"old data"