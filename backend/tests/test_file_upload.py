import io

import pytest

from app.extensions import db
from app.files.hashing import sha256_hex
from app.models import AuditEvent, File, FileVersion, Role, User
from app.seed import seed_roles_and_permissions
from app.storage import StorageError, get_storage

PASSWORD = "Str0ngPass1"
PDF = b"%PDF-1.4\n" + b"hello world\n"


@pytest.fixture(autouse=True)
def seeded(app):
    seed_roles_and_permissions()


def make_user(email="alice@example.com", role="USER"):
    user = User(
        email=email,
        username=email.split("@")[0],
        role=Role.query.filter_by(name=role).first(),
    )
    user.set_password(PASSWORD)
    db.session.add(user)
    db.session.commit()
    return user


def login(client, email="alice@example.com"):
    return client.post("/login", data={"email": email, "password": PASSWORD})


def upload(client, name="report.pdf", data=PDF, mime="application/pdf"):
    return client.post(
        "/api/files/upload",
        data={"file": (io.BytesIO(data), name, mime)},
        content_type="multipart/form-data",
    )


def test_upload_requires_login(client):
    assert upload(client).status_code == 401


def test_upload_stores_file_hash_and_metadata(client):
    user = make_user()
    login(client)
    r = upload(client)
    assert r.status_code == 201
    body = r.get_json()
    assert body["sha256"] == sha256_hex(PDF)
    assert body["size_bytes"] == len(PDF)
    assert body["version"] == 1
    version = FileVersion.query.one()
    assert version.sha256 == sha256_hex(PDF)
    assert version.object_key.startswith(f"users/{user.id}/")
    assert "report" not in version.object_key
    assert get_storage().get_object(version.object_key) == PDF
    event = AuditEvent.query.filter_by(action="UPLOAD").one()
    assert event.status == "SUCCESS"
    assert event.file_id == body["id"]


def test_upload_rejects_executables(client):
    make_user()
    login(client)
    r = upload(client, name="virus.exe", data=b"MZ\x90\x00", mime="application/octet-stream")
    assert r.status_code == 415
    assert File.query.count() == 0
    assert AuditEvent.query.filter_by(action="UPLOAD", status="REJECTED").count() == 1


def test_upload_rejects_wrong_content(client):
    make_user()
    login(client)
    r = upload(client, name="fake.pdf", data=b"\x89PNG\r\n\x1a\n" + b"0" * 8)
    assert r.status_code == 415
    assert File.query.count() == 0


def test_upload_rejects_oversized_files(client):
    make_user()
    login(client)
    r = upload(client, data=b"%PDF-" + b"x" * (1024 * 1024))
    assert r.status_code == 413
    assert File.query.count() == 0


def test_upload_without_file_field(client):
    make_user()
    login(client)
    assert client.post("/api/files/upload", data={}).status_code == 400


def test_upload_neutralises_path_traversal_in_filename(client):
    make_user()
    login(client)
    r = upload(client, name="../../etc/passwd.pdf")
    assert r.status_code == 201
    assert r.get_json()["name"] == "passwd.pdf"
    assert ".." not in FileVersion.query.one().object_key


def test_user_without_upload_permission_gets_403(client):
    guest = Role(name="GUEST")
    db.session.add(guest)
    db.session.commit()
    user = User(email="g@example.com", username="g", role=guest)
    user.set_password(PASSWORD)
    db.session.add(user)
    db.session.commit()
    login(client, "g@example.com")
    assert upload(client).status_code == 403
    assert AuditEvent.query.filter_by(action="ACCESS_DENIED").count() == 1


def test_storage_failure_returns_503_and_saves_nothing(client, monkeypatch):
    make_user()
    login(client)

    def boom(*args, **kwargs):
        raise StorageError("down")

    monkeypatch.setattr(get_storage(), "put_object", boom)
    assert upload(client).status_code == 503
    assert File.query.count() == 0


def test_download_returns_original_bytes(client):
    make_user()
    login(client)
    file_id = upload(client).get_json()["id"]
    r = client.get(f"/api/files/{file_id}/download")
    assert r.status_code == 200
    assert r.data == PDF
    assert "attachment" in r.headers["Content-Disposition"]
    assert AuditEvent.query.filter_by(action="DOWNLOAD").count() == 1


def test_other_users_cannot_see_or_download_a_file(client):
    make_user("alice@example.com")
    make_user("bob@example.com")
    login(client, "alice@example.com")
    file_id = upload(client).get_json()["id"]
    client.post("/logout")
    login(client, "bob@example.com")
    assert client.get(f"/api/files/{file_id}").status_code == 404
    assert client.get(f"/api/files/{file_id}/download").status_code == 404
    assert client.get("/api/files").get_json()["files"] == []
    assert AuditEvent.query.filter_by(action="ACCESS_DENIED").count() == 2


def test_admin_can_download_any_file(client):
    make_user("alice@example.com")
    make_user("root@example.com", role="ADMIN")
    login(client, "alice@example.com")
    file_id = upload(client).get_json()["id"]
    client.post("/logout")
    login(client, "root@example.com")
    assert client.get(f"/api/files/{file_id}/download").status_code == 200


def test_upload_page_requires_login_and_renders(client):
    assert client.get("/files/upload").status_code == 302
    make_user()
    login(client)
    r = client.get("/files/upload")
    assert r.status_code == 200
    assert b"Upload a file" in r.data