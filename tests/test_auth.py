def test_register_login_me(client):
    r = client.post("/api/auth/register", json={"email": "A@Example.com", "password": "password123"})  # ghosttrace:ignore
    assert r.status_code == 201
    assert r.json()["user"]["email"] == "a@example.com"

    assert client.post("/api/auth/register", json={"email": "a@example.com", "password": "password123"}).status_code == 409
    assert client.post("/api/auth/login", json={"email": "a@example.com", "password": "wrong-pass"}).status_code == 401  # ghosttrace:ignore

    token = client.post("/api/auth/login", json={"email": "a@example.com", "password": "password123"}).json()["access_token"]
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200 and me.json()["email"] == "a@example.com"


def test_me_requires_auth(client):
    assert client.get("/api/auth/me").status_code == 401


def _register(client):
    client.post("/api/auth/register", json={"email": "r@example.com", "password": "oldpassword1"})


def _token(monkeypatch):
    sent = {}
    monkeypatch.setattr("app.routers.auth.send_password_reset", lambda user, token: sent.update(token=token))
    return sent


def test_forgot_password_does_not_reveal_accounts(client, monkeypatch):
    sent = _token(monkeypatch)
    _register(client)
    known = client.post("/api/auth/forgot-password", json={"email": "r@example.com"})
    unknown = client.post("/api/auth/forgot-password", json={"email": "nobody@example.com"})
    assert known.status_code == unknown.status_code == 202 and known.json() == unknown.json()
    assert "token" in sent


def test_reset_password_flow_is_single_use(client, monkeypatch):
    sent = _token(monkeypatch)
    _register(client)
    client.post("/api/auth/forgot-password", json={"email": "r@example.com"})
    token = sent["token"]

    assert client.post("/api/auth/reset-password", json={"token": token, "password": "newpassword2"}).status_code == 200
    assert client.post("/api/auth/login", json={"email": "r@example.com", "password": "newpassword2"}).status_code == 200
    assert client.post("/api/auth/login", json={"email": "r@example.com", "password": "oldpassword1"}).status_code == 401
    # the same link cannot be used again
    assert client.post("/api/auth/reset-password", json={"token": token, "password": "another-pass3"}).status_code == 400


def test_reset_token_is_not_a_login_token_and_junk_is_rejected(client, monkeypatch):
    sent = _token(monkeypatch)
    _register(client)
    client.post("/api/auth/forgot-password", json={"email": "r@example.com"})
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {sent['token']}"}).status_code == 401
    assert client.post("/api/auth/reset-password", json={"token": "x" * 40, "password": "newpassword2"}).status_code == 400


def test_auth_endpoints_are_rate_limited(client, monkeypatch):
    from app.config import get_settings
    from app.ratelimit import reset_limits

    monkeypatch.setattr(get_settings(), "rate_limit_enabled", True)
    reset_limits()
    codes = [client.post("/api/auth/login", json={"email": "x@example.com", "password": "wrong-pass-1"}).status_code for _ in range(11)]  # ghosttrace:ignore
    assert codes[:10] == [401] * 10
    assert codes[10] == 429
    reset_limits()


def test_rate_limit_ignores_spoofed_forwarded_for(client, monkeypatch):
    from app.config import get_settings
    from app.ratelimit import reset_limits

    monkeypatch.setattr(get_settings(), "rate_limit_enabled", True)
    monkeypatch.setattr(get_settings(), "trusted_proxy_hops", 1)
    reset_limits()
    # The proxy appends the real address last; a fresh fake address on the left each time must not reset the limit.
    codes = [
        client.post("/api/auth/login", json={"email": "x@example.com", "password": "wrong-pass-1"},  # ghosttrace:ignore
                    headers={"X-Forwarded-For": f"10.0.0.{i}, 203.0.113.7"}).status_code
        for i in range(11)
    ]
    assert codes[10] == 429
    reset_limits()
