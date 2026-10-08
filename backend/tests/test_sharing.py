import io
from datetime import date, datetime, timedelta, timezone

import pytest

from app.extensions import db
from app.models import AuditEvent, File, FileShare, Role, SecurityAlert, User
from app.seed import seed_roles_and_permissions

PASSWORD = "Str0ngPass1"
PDF = b"%PDF-1.4\n" + b"shared document\n"
PDF_B = b"%PDF-1.4\n" + b"second version\n"


@pytest.fixture(autouse=True)
def seeded(app):
    seed_roles_and_permissions()


def make_user(email, role="USER"):
    user = User(
        email=email,
        username=email.split("@")[0],
        role=Role.query.filter_by(name=role).first(),
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


def share(client, file_id, email="bob@example.com", permissions=None, expires=None):
    body = {"email": email, "permissions": ["VIEW", "DOWNLOAD"] if permissions is None else permissions}
    if expires is not None:
        body["expires_at"] = expires
    return client.post(f"/api/files/{file_id}/shares", json=body)


def in_days(days):
    return (date.today() + timedelta(days=days)).isoformat()


def test_sharing_requires_login(client):
    assert client.post("/api/files/1/shares", json={}).status_code == 401
    assert client.get("/api/shared").status_code == 401


def test_owner_shares_file_and_recipient_can_view_and_download(client):
    file_id, alice, bob = setup(client)
    r = share(client, file_id, expires=in_days(30))
    assert r.status_code == 201
    body = r.get_json()
    assert body["permissions"] == ["VIEW", "DOWNLOAD"]
    assert body["active"] is True
    switch(client, "bob@example.com")
    listed = client.get("/api/shared").get_json()["files"]
    assert [f["id"] for f in listed] == [file_id]
    assert listed[0]["owner"] == "alice"
    assert client.get(f"/api/files/{file_id}").status_code == 200
    assert client.get(f"/api/files/{file_id}/download").data == PDF
    event = AuditEvent.query.filter_by(action="SHARE").one()
    assert event.user_id == alice.id
    assert event.details["shared_with"] == bob.id


def test_view_permission_is_always_included(client):
    file_id, _, _ = setup(client)
    r = share(client, file_id, permissions=["DOWNLOAD"])
    assert r.get_json()["permissions"] == ["VIEW", "DOWNLOAD"]


@pytest.mark.parametrize(
    "permissions", [[], ["DELETE"], ["SHARE"], ["VIEW", "UPLOAD"], "VIEW", [1]]
)
def test_invalid_permissions_are_rejected(client, permissions):
    file_id, _, _ = setup(client)
    assert share(client, file_id, permissions=permissions).status_code == 400
    assert FileShare.query.count() == 0


@pytest.mark.parametrize("value", ["2000-01-01", "yesterday", "2999-12-31", 12345])
def test_invalid_expiry_is_rejected(client, value):
    file_id, _, _ = setup(client)
    assert share(client, file_id, expires=value).status_code == 400
    assert FileShare.query.count() == 0


def test_recipient_must_exist_be_active_and_differ_from_owner(client):
    file_id, alice, bob = setup(client)
    assert share(client, file_id, email="nobody@example.com").status_code == 404
    assert share(client, file_id, email="alice@example.com").status_code == 400
    bob.is_active = False
    db.session.commit()
    assert share(client, file_id).status_code == 404
    assert FileShare.query.count() == 0


def test_sharing_again_updates_the_existing_share(client):
    file_id, _, _ = setup(client)
    first = share(client, file_id, permissions=["VIEW"])
    second = share(client, file_id, permissions=["VIEW", "DOWNLOAD", "MODIFY"])
    assert first.status_code == 201
    assert second.status_code == 200
    assert FileShare.query.count() == 1
    assert FileShare.query.one().permissions == ["VIEW", "DOWNLOAD", "MODIFY"]


def test_non_owner_cannot_share_or_list_shares(client):
    file_id, _, _ = setup(client)
    make_user("carol@example.com")
    switch(client, "bob@example.com")
    assert share(client, file_id, email="carol@example.com").status_code == 404
    assert client.get(f"/api/files/{file_id}/shares").status_code == 404
    assert FileShare.query.count() == 0
    assert SecurityAlert.query.filter_by(alert_type="UNAUTHORIZED_ACCESS").count() == 2


def test_revoking_a_share_removes_access(client):
    file_id, _, _ = setup(client)
    share_id = share(client, file_id).get_json()["id"]
    r = client.delete(f"/api/files/{file_id}/shares/{share_id}")
    assert r.status_code == 200
    assert r.get_json()["revoked"] is True
    assert client.delete(f"/api/files/{file_id}/shares/{share_id}").status_code == 400
    switch(client, "bob@example.com")
    assert client.get(f"/api/files/{file_id}").status_code == 404
    assert client.get("/api/shared").get_json()["files"] == []
    assert AuditEvent.query.filter_by(action="UNSHARE").count() == 1
    assert SecurityAlert.query.filter_by(alert_type="UNAUTHORIZED_ACCESS").count() == 1


def test_share_id_must_belong_to_the_file(client):
    file_id, _, _ = setup(client)
    other_id = upload(client, "other.pdf", PDF_B).get_json()["id"]
    share_id = share(client, file_id).get_json()["id"]
    assert client.delete(f"/api/files/{other_id}/shares/{share_id}").status_code == 404
    assert FileShare.query.one().revoked_at is None


def test_expired_share_fails_automatically_and_raises_alert(client):
    file_id, _, _ = setup(client)
    share(client, file_id, expires=in_days(5))
    FileShare.query.one().expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db.session.commit()
    switch(client, "bob@example.com")
    assert client.get(f"/api/files/{file_id}").status_code == 404
    assert client.get(f"/api/files/{file_id}/download").status_code == 404
    assert client.get("/api/shared").get_json()["files"] == []
    assert SecurityAlert.query.filter_by(alert_type="EXPIRED_ACCESS").count() == 2


def test_recipient_is_limited_to_the_granted_permissions(client):
    file_id, _, _ = setup(client)
    share(client, file_id, permissions=["VIEW", "DOWNLOAD"])
    switch(client, "bob@example.com")
    assert client.patch(f"/api/files/{file_id}", json={"name": "x.pdf"}).status_code == 404
    assert client.delete(f"/api/files/{file_id}").status_code == 404
    new_version = client.post(
        f"/api/files/{file_id}/versions",
        data={"file": (io.BytesIO(PDF_B), "report.pdf", "application/pdf")},
        content_type="multipart/form-data",
    )
    assert new_version.status_code == 404
    assert File.query.one().name == "report.pdf"


def test_modify_share_allows_rename_but_not_delete_or_resharing(client):
    file_id, _, _ = setup(client)
    share(client, file_id, permissions=["VIEW", "MODIFY"])
    switch(client, "bob@example.com")
    assert client.patch(f"/api/files/{file_id}", json={"name": "renamed.pdf"}).status_code == 200
    assert client.delete(f"/api/files/{file_id}").status_code == 404
    assert share(client, file_id, email="alice@example.com").status_code == 404


def test_admin_can_manage_shares_of_any_file(client):
    file_id, _, _ = setup(client)
    make_user("root@example.com", role="ADMIN")
    switch(client, "root@example.com")
    assert share(client, file_id).status_code == 201
    shares = client.get(f"/api/files/{file_id}/shares").get_json()["shares"]
    assert len(shares) == 1


def test_role_without_share_permission_gets_403(client):
    guest_role = Role(name="GUEST")
    db.session.add(guest_role)
    db.session.commit()
    guest = User(email="g@example.com", username="g", role=guest_role)
    guest.set_password(PASSWORD)
    db.session.add(guest)
    db.session.commit()
    guest_file = File(owner=guest, name="a.pdf")
    db.session.add(guest_file)
    db.session.commit()
    make_user("bob@example.com")
    login(client, "g@example.com")
    assert share(client, guest_file.id).status_code == 403


def test_deleted_files_leave_the_shared_list(client):
    file_id, _, _ = setup(client)
    share(client, file_id)
    client.delete(f"/api/files/{file_id}")
    switch(client, "bob@example.com")
    assert client.get("/api/shared").get_json()["files"] == []


def test_sharing_pages(client):
    assert client.get("/shared").status_code == 302
    file_id, _, _ = setup(client)
    assert client.get(f"/files/{file_id}/share").status_code == 200
    assert client.get("/shared").status_code == 200
    switch(client, "bob@example.com")
    assert client.get(f"/files/{file_id}/share").status_code == 404