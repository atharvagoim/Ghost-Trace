import os

# Tests use an in-memory MongoDB (mongomock) by default: no database server needed.
os.environ["MONGODB_URI"] = os.environ.get("TEST_MONGODB_URI", "mongomock://")  # set TEST_MONGODB_URI to test a real server
os.environ["MONGODB_DB"] = "ghosttrace_test"
os.environ["ENABLE_SCHEDULER"] = "false"
os.environ["RATE_LIMIT_ENABLED"] = "false"
os.environ["SECRET_KEY"] = "test-secret-key-that-is-long-enough-123"
os.environ.pop("VERCEL", None)

import pytest
from fastapi.testclient import TestClient

from app.db import client as mongo_client, ensure_indexes, get_db
from app.main import app


@pytest.fixture()
def client():
    mongo_client().drop_database("ghosttrace_test")
    ensure_indexes(get_db())
    with TestClient(app) as c:
        yield c
    mongo_client().drop_database("ghosttrace_test")


@pytest.fixture()
def auth_client(client):
    r = client.post("/api/auth/register", json={"email": "dev@example.com", "password": "supersecret1", "full_name": "Dev"})  # ghosttrace:ignore
    assert r.status_code == 201, r.text
    client.headers["Authorization"] = f"Bearer {r.json()['access_token']}"
    return client
