import time
from collections import defaultdict, deque
from threading import Lock

from fastapi import HTTPException, Request, status

from .config import get_settings

_hits: dict[str, deque[float]] = defaultdict(deque)
_lock = Lock()


def reset_limits() -> None:
    with _lock:
        _hits.clear()


def client_ip(request: Request, hops: int) -> str:
    """Client address for rate limiting. Each trusted proxy appends the address it saw to X-Forwarded-For,
    so the entry `hops` from the right is the real client; anything left of it is client-supplied and spoofable."""
    peer = request.client.host if request.client else "unknown"
    if hops <= 0:
        return peer
    forwarded = [h.strip() for h in request.headers.get("x-forwarded-for", "").split(",") if h.strip()]
    return forwarded[-hops] if len(forwarded) >= hops else peer


_last_sweep = 0.0


def _sweep(now: float, horizon: float) -> None:
    """Drop clients whose hits have all expired, so the table can't grow without bound."""
    global _last_sweep
    if now - _last_sweep < 60:
        return
    _last_sweep = now
    for key in [k for k, hits in _hits.items() if not hits or now - hits[-1] > horizon]:
        del _hits[key]


def check_limit(name: str, client: str, limit: int, window_seconds: int, request: Request | None = None) -> None:
    """Sliding-window check for an arbitrary key (an address, an account...). Raises 429 when over the limit."""
    if not get_settings().rate_limit_enabled:
        return
    key, now = f"{name}:{client}", time.monotonic()
    with _lock:
        _sweep(now, max(window_seconds, 3600))
        hits = _hits[key]
        while hits and now - hits[0] > window_seconds:
            hits.popleft()
        if len(hits) >= limit:
            retry = max(1, int(window_seconds - (now - hits[0])))
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "Too many attempts. Please wait a bit and try again.",
                headers={"Retry-After": str(retry)},
            )
        hits.append(now)


def rate_limit(name: str, limit: int, window_seconds: int):
    """Per-client sliding-window limiter, used as a route dependency (in-memory, so per process)."""

    def dependency(request: Request) -> None:
        check_limit(name, client_ip(request, get_settings().trusted_proxy_hops), limit, window_seconds, request)

    return dependency
