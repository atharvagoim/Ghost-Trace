"""Breach intelligence: email breach lookups (XposedOrNot, optionally HIBP) and Pwned Passwords k-anonymity checks."""

import hashlib
import math
import re

import httpx

from ..config import get_settings


class BreachLookupError(Exception):
    pass


SENSITIVE_DATA = {"passwords": 30, "password hints": 10, "credit cards": 30, "bank account numbers": 30,
                  "social security numbers": 30, "government issued ids": 25, "security questions and answers": 15,
                  "auth tokens": 25, "phone numbers": 6, "physical addresses": 6, "dates of birth": 6}


def _risk_from(breaches: list[dict], data_classes: list[str]) -> float:
    if not breaches:
        return 0.0
    base = min(45, 15 * math.log2(1 + len(breaches)))
    sens = sum(SENSITIVE_DATA.get(dc.lower(), 2) for dc in data_classes)
    return round(min(100.0, base + min(55, sens)), 1)


async def check_email(email: str) -> dict:
    s = get_settings()
    if s.hibp_api_key:
        return await _check_hibp(email, s.hibp_api_key)
    return await _check_xposedornot(email, s.xposedornot_api_url)


async def _check_xposedornot(email: str, base: str) -> dict:
    async with httpx.AsyncClient(timeout=25, headers={"User-Agent": "GhostTrace"}) as client:
        try:
            resp = await client.get(f"{base}/breach-analytics", params={"email": email})
        except httpx.HTTPError as exc:
            raise BreachLookupError(f"Could not reach the breach database: {exc}") from exc
    if resp.status_code == 404:
        return {"breaches": [], "data_classes": [], "risk": 0.0, "source": "xposedornot"}
    if resp.status_code == 429:
        raise BreachLookupError("The breach database is rate limiting requests. Try again in a minute.")
    if resp.status_code >= 400:
        raise BreachLookupError(f"Breach database returned {resp.status_code}.")
    data = resp.json() or {}
    details = ((data.get("ExposedBreaches") or {}).get("breaches_details")) or []
    if not details:
        return {"breaches": [], "data_classes": [], "risk": 0.0, "source": "xposedornot"}
    breaches = []
    classes: set[str] = set()
    for b in details:
        xposed = [c.strip() for c in re.split(r";", b.get("xposed_data") or "") if c.strip()]
        classes.update(xposed)
        breaches.append({
            "name": b.get("breach"),
            "domain": b.get("domain"),
            "date": str(b.get("xposed_date") or ""),
            "records": b.get("xposed_records"),
            "data": xposed,
            "description": b.get("details"),
            "industry": b.get("industry"),
            "password_risk": b.get("password_risk"),
            "verified": b.get("verified") == "Yes",
            "logo": b.get("logo"),
        })
    breaches.sort(key=lambda b: b["date"], reverse=True)
    data_classes = sorted(classes)
    return {"breaches": breaches, "data_classes": data_classes, "risk": _risk_from(breaches, data_classes), "source": "xposedornot"}


async def _check_hibp(email: str, key: str) -> dict:
    headers = {"hibp-api-key": key, "User-Agent": "GhostTrace"}
    async with httpx.AsyncClient(timeout=25, headers=headers) as client:
        try:
            resp = await client.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}", params={"truncateResponse": "false"})
        except httpx.HTTPError as exc:
            raise BreachLookupError(f"Could not reach Have I Been Pwned: {exc}") from exc
    if resp.status_code == 404:
        return {"breaches": [], "data_classes": [], "risk": 0.0, "source": "hibp"}
    if resp.status_code == 401:
        raise BreachLookupError("The HIBP API key was rejected.")
    if resp.status_code == 429:
        raise BreachLookupError("Have I Been Pwned is rate limiting requests. Try again shortly.")
    if resp.status_code >= 400:
        raise BreachLookupError(f"Have I Been Pwned returned {resp.status_code}.")
    breaches, classes = [], set()
    for b in resp.json():
        classes.update(b.get("DataClasses", []))
        breaches.append({
            "name": b.get("Title") or b.get("Name"), "domain": b.get("Domain"), "date": b.get("BreachDate"),
            "records": b.get("PwnCount"), "data": b.get("DataClasses", []), "description": re.sub(r"<[^>]+>", "", b.get("Description", "")),
            "industry": None, "password_risk": None, "verified": b.get("IsVerified"), "logo": b.get("LogoPath"),
        })
    breaches.sort(key=lambda b: b["date"] or "", reverse=True)
    data_classes = sorted(classes)
    return {"breaches": breaches, "data_classes": data_classes, "risk": _risk_from(breaches, data_classes), "source": "hibp"}


async def pwned_password_count(password: str) -> int:
    """k-anonymity: only the first 5 hex chars of the SHA-1 hash leave the server."""
    digest = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    base = get_settings().pwned_passwords_api_url
    async with httpx.AsyncClient(timeout=20, headers={"User-Agent": "GhostTrace", "Add-Padding": "true"}) as client:
        try:
            resp = await client.get(f"{base}/range/{prefix}")
        except httpx.HTTPError as exc:
            raise BreachLookupError(f"Could not reach Pwned Passwords: {exc}") from exc
    if resp.status_code != 200:
        raise BreachLookupError(f"Pwned Passwords returned {resp.status_code}.")
    for line in resp.text.splitlines():
        h, _, count = line.partition(":")
        if h.strip() == suffix:
            return int(count.strip() or 0)
    return 0


def password_strength(password: str) -> tuple[int, str, list[str]]:
    """Return (0-4 score, label, feedback) using length, character variety and common patterns."""
    feedback = []
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", password):
        pool += 33
    bits = len(password) * math.log2(pool) if pool else 0
    if re.search(r"(.)\1{2,}", password):
        bits -= 10
        feedback.append("Avoid repeated characters.")
    if re.search(r"(?i)(password|qwerty|letmein|admin|welcome|123456|abc123|iloveyou)", password):
        bits -= 25
        feedback.append("Contains a very common word or sequence.")
    if re.search(r"(19|20)\d{2}", password):
        bits -= 6
        feedback.append("Years are easy to guess.")
    if len(password) < 12:
        feedback.append("Use at least 12 characters; a passphrase of 4+ random words works well.")
    if pool < 62:
        feedback.append("Mix upper and lower case, numbers and symbols.")
    score = 0 if bits < 28 else 1 if bits < 40 else 2 if bits < 60 else 3 if bits < 80 else 4
    label = ["Very weak", "Weak", "Fair", "Strong", "Very strong"][score]
    return score, label, feedback
