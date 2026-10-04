import pytest

from app.auth import services
from app.extensions import db
from app.models import Role, SecurityAlert, User
from app.seed import seed_roles_and_permissions

PASSWORD = "Str0ngPass1"


@pytest.fixture(autouse=True)
def seeded(app):
    seed_roles_and_permissions()


def make_user(email="alice@example.com", role="USER", password=PASSWORD):
    user = User(
        email=email,
        username=email.split("@")[0],
        role=Role.query.filter_by(name=role).first(),
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return user


def login(client, email="alice@example.com", password=PASSWORD, **extra):
    return client.post("/login", data={"email": email, "password": password, **extra})


def register_data(**overrides):
    data = {
        "email": "bob@example.com",
        "username": "bob",
        "password": PASSWORD,
        "confirm_password": PASSWORD,
    }
    data.update(overrides)
    return data


def test_register_creates_user_with_hashed_password(client):
    r = client.post("/register", data=register_data(email="Bob@Example.com"))
    assert r.status_code == 302
    user = User.query.filter_by(email="bob@example.com").first()
    assert user.role.name == "USER"
    assert PASSWORD not in user.password_hash
    assert user.check_password(PASSWORD)


def test_register_rejects_weak_password(client):
    r = client.post("/register", data=register_data(password="short", confirm_password="short"))
    assert r.status_code == 400
    assert User.query.count() == 0


def test_register_rejects_duplicate_email(client):
    make_user("bob@example.com")
    r = client.post("/register", data=register_data(username="other"))
    assert r.status_code == 400
    assert User.query.count() == 1


def test_login_success_and_dashboard(client):
    make_user()
    r = login(client)
    assert r.status_code == 302
    assert r.headers["Location"].endswith("/dashboard")
    assert client.get("/dashboard").status_code == 200


def test_dashboard_requires_login(client):
    r = client.get("/dashboard")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_api_requires_login_returns_json_401(client):
    r = client.get("/api/auth/me")
    assert r.status_code == 401
    assert r.get_json()["error"] == "Unauthorized"


def test_wrong_password_is_rejected_and_counted(client):
    make_user()
    r = login(client, password="WrongPass1")
    assert r.status_code == 401
    assert User.query.first().failed_login_count == 1


def test_account_locks_after_repeated_failures(client):
    make_user()
    for _ in range(services.MAX_FAILED_ATTEMPTS):
        login(client, password="WrongPass1")
    r = login(client)  # even the correct password is refused while locked
    assert r.status_code == 401
    assert b"locked" in r.data.lower()
    assert SecurityAlert.query.filter_by(alert_type="FAILED_LOGIN").count() == 1


def test_deactivated_user_cannot_login(client):
    user = make_user()
    user.is_active = False
    db.session.commit()
    r = login(client)
    assert r.status_code == 401
    assert SecurityAlert.query.filter_by(alert_type="DISABLED_USER_ACCESS").count() == 1


def test_login_ignores_external_redirect(client):
    make_user()
    r = login(client, next="https://evil.example.com")
    assert r.headers["Location"].endswith("/dashboard")


def test_login_follows_safe_next(client):
    make_user()
    r = login(client, next="/change-password")
    assert r.headers["Location"].endswith("/change-password")


def test_logout_ends_session(client):
    make_user()
    login(client)
    assert client.post("/logout").status_code == 302
    assert client.get("/dashboard").status_code == 302


def test_change_password(client):
    make_user()
    login(client)
    r = client.post(
        "/change-password",
        data={
            "current_password": PASSWORD,
            "new_password": "NewPassw0rd",
            "confirm_password": "NewPassw0rd",
        },
    )
    assert r.status_code == 302
    assert User.query.first().check_password("NewPassw0rd")


def test_change_password_needs_correct_current_password(client):
    make_user()
    login(client)
    r = client.post(
        "/change-password",
        data={
            "current_password": "Nope12345",
            "new_password": "NewPassw0rd",
            "confirm_password": "NewPassw0rd",
        },
    )
    assert r.status_code == 400
    assert User.query.first().check_password(PASSWORD)


def test_reset_token_is_single_use(app):
    user = make_user()
    token = services.make_reset_token(user)
    assert services.verify_reset_token(token).id == user.id
    user.set_password("AnotherPass1")
    db.session.commit()
    assert services.verify_reset_token(token) is None


def test_reset_password_flow(client):
    user = make_user()
    token = services.make_reset_token(user)
    r = client.post(
        f"/reset-password/{token}",
        data={"password": "ResetPass1", "confirm_password": "ResetPass1"},
    )
    assert r.status_code == 302
    assert User.query.first().check_password("ResetPass1")


def test_only_admin_can_deactivate_users(client):
    make_user("admin@example.com", role="ADMIN")
    target = make_user("bob@example.com")
    make_user("carol@example.com")
    login(client, "carol@example.com")
    assert client.post(f"/api/users/{target.id}/deactivate").status_code == 403
    client.post("/logout")
    login(client, "admin@example.com")
    r = client.post(f"/api/users/{target.id}/deactivate")
    assert r.status_code == 200
    assert r.get_json()["is_active"] is False


def test_deactivation_ends_existing_session(client):
    user = make_user()
    login(client)
    user.is_active = False
    db.session.commit()
    assert client.get("/dashboard").status_code == 302