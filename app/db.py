"""MongoDB access.

Documents keep small integer ids (a `counters` collection hands them out), so URLs stay short (/app/scans/12) and the API
looks exactly as it did before. Each collection's documents use that integer as `_id`.

MONGODB_URI chooses the server. `mongomock://` (the default when it is unset, outside Vercel) is an in-memory fake that
needs no server: handy for tests and a first local run, but everything is lost when the process stops.
"""

import logging
from datetime import datetime, timezone
from typing import Any

from pymongo import ASCENDING, DESCENDING, MongoClient, ReturnDocument
from pymongo.database import Database

from .config import get_settings

log = logging.getLogger("ghosttrace.db")
_client: Any = None


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Doc(dict):
    """A Mongo document with attribute access (`scan.status`) and `id` as an alias of `_id`.
    Missing fields read as None, so optional fields behave like nullable columns."""

    def __getattr__(self, key: str) -> Any:
        if key == "id":
            return self.get("_id")
        if key.startswith("__"):
            raise AttributeError(key)
        return self.get(key)

    def __setattr__(self, key: str, value: Any) -> None:
        self["_id" if key == "id" else key] = value


def wrap(d: dict | None) -> Doc | None:
    return Doc(d) if d is not None else None


def client():
    global _client
    if _client is None:
        uri = get_settings().mongodb_uri
        if uri.startswith("mongomock://"):
            import mongomock

            _client = mongomock.MongoClient(tz_aware=True)
        else:
            # Small pool: serverless instances are many and short-lived. tz_aware returns UTC-aware datetimes.
            _client = MongoClient(uri, appname="ghosttrace", tz_aware=True, maxPoolSize=10, serverSelectionTimeoutMS=8000)
    return _client


def get_db() -> Database:
    """FastAPI dependency and general accessor. The client is shared and thread-safe, so there is nothing to close."""
    return client()[get_settings().mongodb_db]


def next_id(db: Database, name: str) -> int:
    row = db.counters.find_one_and_update({"_id": name}, {"$inc": {"seq": 1}}, upsert=True, return_document=ReturnDocument.AFTER)
    return int(row["seq"])


def insert(db: Database, collection: str, data: dict) -> Doc:
    """Insert with the next integer id and created_at (unless given); returns the stored document."""
    doc = Doc(data)
    doc["_id"] = next_id(db, collection)
    doc.setdefault("created_at", utcnow())
    db[collection].insert_one(doc)
    return doc


def find(db: Database, collection: str, query: dict, sort: list | None = None, limit: int = 0, skip: int = 0,
         projection: dict | None = None) -> list[Doc]:
    cur = db[collection].find(query, projection)
    if sort:
        cur = cur.sort(sort)
    if skip:
        cur = cur.skip(skip)
    if limit:
        cur = cur.limit(limit)
    return [Doc(d) for d in cur]


def find_one(db: Database, collection: str, query: dict) -> Doc | None:
    return wrap(db[collection].find_one(query))


def ensure_indexes(db: Database) -> None:
    db.users.create_index("email", unique=True)
    db.monitors.create_index([("user_id", ASCENDING), ("target_type", ASCENDING), ("target", ASCENDING)], unique=True)
    db.scans.create_index([("user_id", ASCENDING), ("created_at", DESCENDING)])
    db.scans.create_index([("status", ASCENDING), ("created_at", ASCENDING)])
    db.findings.create_index([("user_id", ASCENDING), ("status", ASCENDING), ("risk_score", DESCENDING)])
    db.findings.create_index([("user_id", ASCENDING), ("fingerprint", ASCENDING)])
    db.findings.create_index("scan_id")
    db.breach_checks.create_index([("user_id", ASCENDING), ("checked_at", DESCENDING)])
    db.alerts.create_index([("user_id", ASCENDING), ("created_at", DESCENDING)])


def reset_client() -> None:
    """Forget the cached client (tests switch databases between runs)."""
    global _client
    _client = None
