def test_request_id_header_is_set(client):
    assert client.get("/api/health").headers.get("X-Request-ID")


def test_request_id_is_echoed_back(client):
    r = client.get("/api/health", headers={"X-Request-ID": "abc-123"})
    assert r.headers["X-Request-ID"] == "abc-123"