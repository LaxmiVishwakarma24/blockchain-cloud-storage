def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.get_json() == {
        "status": "healthy",
        "application": "Blockchain Cloud Storage",
        "version": "1.0.0",
    }


def test_health_db(client):
    assert client.get("/api/health/db").get_json() == {"database": "connected"}


def test_index_page(client):
    assert b"Blockchain Cloud Storage" in client.get("/").data