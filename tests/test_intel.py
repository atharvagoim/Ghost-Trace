from app.intel import breach


def test_password_endpoint(auth_client, monkeypatch):
    async def fake_count(pw):
        return 52256179 if pw == "password" else 0

    monkeypatch.setattr("app.routers.breach.pwned_password_count", fake_count)
    r = auth_client.post("/api/breach/password", json={"password": "password"}).json()  # ghosttrace:ignore
    assert r["pwned"] and r["strength_label"] == "Compromised"
    r = auth_client.post("/api/breach/password", json={"password": "violet-anchor-quartz-meadow-71"}).json()  # ghosttrace:ignore
    assert not r["pwned"] and r["strength"] >= 3


def test_email_breach_and_monitor(auth_client, monkeypatch):
    async def fake_check(email):
        return {"breaches": [{"name": "LinkedIn", "date": "2016", "data": ["Passwords", "Email addresses"]}],
                "data_classes": ["Email addresses", "Passwords"], "risk": breach._risk_from([{}], ["Passwords"]), "source": "xposedornot"}

    monkeypatch.setattr("app.routers.breach.check_email", fake_check)
    r = auth_client.post("/api/breach/email", json={"email": "Dev@Example.com"})
    assert r.status_code == 200 and r.json()["breach_count"] == 1 and r.json()["email"] == "dev@example.com"
    assert len(auth_client.get("/api/breach/history").json()) == 1

    m = auth_client.post("/api/monitors", json={"target_type": "email", "target": "dev@example.com"})
    assert m.status_code == 201
    assert auth_client.post("/api/monitors", json={"target_type": "email", "target": "dev@example.com"}).status_code == 409
    assert auth_client.patch(f"/api/monitors/{m.json()['id']}", json={"enabled": False}).json()["enabled"] is False


def test_strength_scoring():
    assert breach.password_strength("password1")[0] <= 1
    assert breach.password_strength("Gx7#pQ2!vL9@wZ4$")[0] == 4
