import io
from datetime import datetime, timedelta, timezone

import pytest

from app.extensions import db
from app.models import AuditEvent, File, FileShare, FileVersion, Role, SecurityAlert, User
from app.seed import seed_roles_and_permissions
from app.storage import get_storage

PASSWORD = "Str0ngPass1"
PDF_A = b"%PDF-1.4\n" + b"first version\n"
PDF_B = b"%PDF-1.4\n" + b"second version\n"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16


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


def upload(client, name="report.pdf", data=PDF_A, mime="application/pdf"):
    return client.post(
        "/api/files/upload",
        data={"file": (io.BytesIO(data), name, mime)},
        content_type="multipart/form-data",
    )


def new_version(client, file_id, data=PDF_B, name="report.pdf", mime="application/pdf"):
    return client.post(
        f"/api/files/{file_id}/versions",
        data={"file": (io.BytesIO(data), name, mime)},
        content_type="multipart/form-data",
    )


def test_rename_keeps_extension_and_is_audited(client):
    make_user()
    login(client)
    fid = upload(client).get_json()["id"]
    r = client.patch(f"/api/files/{fid}", json={"name": "q3-report.pdf"})
    assert r.status_code == 200
    assert r.get_json()["name"] == "q3-report.pdf"
    assert client.patch(f"/api/files/{fid}", json={"name": "q3.txt"}).status_code == 400
    r = client.patch(f"/api/files/{fid}", json={"name": "../../evil.pdf"})
    assert r.get_json()["name"] == "evil.pdf"
    event = AuditEvent.query.filter_by(action="MODIFY").first()
    assert event.details["operation"] == "rename"


def test_rename_rejects_bad_requests(client):
    make_user()
    login(client)
    fid = upload(client).get_json()["id"]
    url = f"/api/files/{fid}"
    assert client.patch(url, json={}).status_code == 400
    assert client.patch(url, json={"name": 123}).status_code == 400
    assert client.patch(url, data="not json").status_code == 400
    assert client.patch(url, json={"name": "noextension"}).status_code == 415
    assert File.query.one().name == "report.pdf"


def test_other_users_cannot_rename_delete_or_restore(client):
    make_user("alice@example.com")
    make_user("bob@example.com")
    login(client, "alice@example.com")
    fid = upload(client).get_json()["id"]
    client.post("/logout")
    login(client, "bob@example.com")
    assert client.patch(f"/api/files/{fid}", json={"name": "mine.pdf"}).status_code == 404
    assert client.delete(f"/api/files/{fid}").status_code == 404
    assert client.post(f"/api/files/{fid}/restore").status_code == 404
    file = File.query.one()
    assert file.name == "report.pdf"
    assert file.is_deleted is False
    assert SecurityAlert.query.filter_by(alert_type="UNAUTHORIZED_ACCESS").count() == 1
    assert SecurityAlert.query.filter_by(alert_type="UNAUTHORIZED_DELETE").count() == 2


def test_soft_delete_hides_file_and_restore_brings_it_back(client):
    make_user()
    login(client)
    fid = upload(client).get_json()["id"]
    r = client.delete(f"/api/files/{fid}")
    assert r.status_code == 200
    assert r.get_json()["deleted"] is True
    assert client.get(f"/api/files/{fid}").status_code == 404
    assert client.get(f"/api/files/{fid}/download").status_code == 404
    assert client.get("/api/files").get_json()["files"] == []
    trash = client.get("/api/files?view=trash").get_json()["files"]
    assert [f["id"] for f in trash] == [fid]
    assert FileVersion.query.count() == 1  # data is kept so it can be restored
    r = client.post(f"/api/files/{fid}/restore")
    assert r.status_code == 200
    assert r.get_json()["deleted"] is False
    assert client.get(f"/api/files/{fid}/download").data == PDF_A
    assert AuditEvent.query.filter_by(action="DELETE").count() == 1


def test_restore_of_a_file_that_is_not_deleted_is_rejected(client):
    make_user()
    login(client)
    fid = upload(client).get_json()["id"]
    assert client.post(f"/api/files/{fid}/restore").status_code == 400


def test_list_search_filter_sort_and_pagination(client):
    make_user()
    login(client)
    upload(client, "alpha.pdf", PDF_A)
    upload(client, "beta.txt", b"hello", "text/plain")
    upload(client, "gamma.pdf", PDF_B)

    def names(query):
        return [f["name"] for f in client.get("/api/files?" + query).get_json()["files"]]

    assert names("q=alp") == ["alpha.pdf"]
    assert names("q=%25") == []  # a literal % is not a wildcard
    assert names("type=txt") == ["beta.txt"]
    assert sorted(names("type=pdf")) == ["alpha.pdf", "gamma.pdf"]
    assert names("sort=name&order=asc") == ["alpha.pdf", "beta.txt", "gamma.pdf"]
    page2 = client.get("/api/files?sort=name&order=asc&per_page=2&page=2").get_json()
    assert [f["name"] for f in page2["files"]] == ["gamma.pdf"]
    assert page2["total"] == 3


def test_list_date_range_filter(client):
    make_user()
    login(client)
    upload(client, "alpha.pdf", PDF_A)
    upload(client, "gamma.pdf", PDF_B)
    assert len(client.get("/api/files?from=2000-01-01&to=2999-12-31").get_json()["files"]) == 2
    assert client.get("/api/files?from=2999-01-01").get_json()["files"] == []


def test_list_rejects_bad_filters(client):
    make_user()
    login(client)
    assert client.get("/api/files?type=exe").status_code == 400
    assert client.get("/api/files?from=yesterday").status_code == 400


def test_new_version_keeps_history_and_old_versions_stay_downloadable(client):
    make_user()
    login(client)
    fid = upload(client, data=PDF_A).get_json()["id"]
    r = new_version(client, fid, PDF_B)
    assert r.status_code == 201
    assert r.get_json()["version"] == 2
    versions = client.get(f"/api/files/{fid}/versions").get_json()["versions"]
    assert [v["version"] for v in versions] == [2, 1]
    assert client.get(f"/api/files/{fid}/download").data == PDF_B
    assert client.get(f"/api/files/{fid}/versions/1/download").data == PDF_A
    assert client.get(f"/api/files/{fid}").get_json()["version"] == 2
    assert all(get_storage().get_object(v.object_key)[0] == 1 for v in FileVersion.query.all())


def test_new_version_must_be_the_same_file_type(client):
    make_user()
    login(client)
    fid = upload(client).get_json()["id"]
    r = new_version(client, fid, PNG, name="x.png", mime="image/png")
    assert r.status_code == 415
    assert FileVersion.query.count() == 1


def test_restoring_an_old_version_creates_a_new_version(client):
    make_user()
    login(client)
    fid = upload(client, data=PDF_A).get_json()["id"]
    new_version(client, fid, PDF_B)
    r = client.post(f"/api/files/{fid}/versions/1/restore")
    assert r.status_code == 201
    assert r.get_json()["version"] == 3
    assert client.get(f"/api/files/{fid}/download").data == PDF_A
    v1, v2, v3 = FileVersion.query.order_by(FileVersion.version_number).all()
    assert v3.sha256 == v1.sha256
    assert v3.sha256 != v2.sha256
    assert len({v1.object_key, v2.object_key, v3.object_key}) == 3
    event = AuditEvent.query.filter_by(action="MODIFY").order_by(AuditEvent.id.desc()).first()
    assert event.details["restored_from"] == 1


def test_restore_refuses_a_tampered_old_version(client):
    make_user()
    login(client)
    fid = upload(client, data=PDF_A).get_json()["id"]
    new_version(client, fid, PDF_B)
    v1 = FileVersion.query.filter_by(version_number=1).one()
    storage = get_storage()
    blob = bytearray(storage.get_object(v1.object_key))
    blob[-1] ^= 0x01
    storage.put_object(v1.object_key, bytes(blob))
    r = client.post(f"/api/files/{fid}/versions/1/restore")
    assert r.status_code == 409
    assert FileVersion.query.count() == 2
    assert SecurityAlert.query.filter_by(alert_type="HASH_MISMATCH").count() == 1


def test_other_users_cannot_use_version_endpoints(client):
    make_user("alice@example.com")
    make_user("bob@example.com")
    login(client, "alice@example.com")
    fid = upload(client).get_json()["id"]
    client.post("/logout")
    login(client, "bob@example.com")
    assert client.get(f"/api/files/{fid}/versions").status_code == 404
    assert client.get(f"/api/files/{fid}/versions/1/download").status_code == 404
    assert new_version(client, fid).status_code == 404
    assert client.post(f"/api/files/{fid}/versions/1/restore").status_code == 404
    assert FileVersion.query.count() == 1


def test_pages_render_and_are_protected(client):
    make_user("alice@example.com")
    make_user("bob@example.com")
    assert client.get("/files").status_code == 302
    login(client, "alice@example.com")
    fid = upload(client).get_json()["id"]
    r = client.get("/files")
    assert r.status_code == 200
    assert b"My files" in r.data
    r = client.get(f"/files/{fid}/versions")
    assert r.status_code == 200
    assert b"report.pdf" in r.data
    client.post("/logout")
    login(client, "bob@example.com")
    assert client.get(f"/files/{fid}/versions").status_code == 404


def test_a_share_grants_only_the_listed_permissions(client):
    alice = make_user("alice@example.com")
    bob = make_user("bob@example.com")
    login(client, "alice@example.com")
    fid = upload(client).get_json()["id"]
    client.post("/logout")
    db.session.add(
        FileShare(file_id=fid, shared_with_id=bob.id, shared_by_id=alice.id, permissions=["VIEW", "DOWNLOAD"])
    )
    db.session.commit()
    login(client, "bob@example.com")
    assert client.get(f"/api/files/{fid}").status_code == 200
    assert client.get(f"/api/files/{fid}/download").data == PDF_A
    assert client.patch(f"/api/files/{fid}", json={"name": "x.pdf"}).status_code == 404
    assert client.delete(f"/api/files/{fid}").status_code == 404


def test_an_expired_share_stops_working(client):
    alice = make_user("alice@example.com")
    bob = make_user("bob@example.com")
    login(client, "alice@example.com")
    fid = upload(client).get_json()["id"]
    client.post("/logout")
    past = datetime.now(timezone.utc) - timedelta(days=1)
    db.session.add(
        FileShare(
            file_id=fid, shared_with_id=bob.id, shared_by_id=alice.id,
            permissions=["VIEW", "DOWNLOAD"], expires_at=past,
        )
    )
    db.session.commit()
    login(client, "bob@example.com")
    assert client.get(f"/api/files/{fid}").status_code == 404