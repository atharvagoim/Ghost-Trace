"""Redaction for everything that leaves for the AI provider, and for what comes back.

Layers, applied in order to any text:
1. GhostTrace's own detection engine (all detection rules, entropy, placeholder logic). Every match is replaced by a typed
   placeholder such as [REDACTED:aws_access_key_id]. Email addresses become [REDACTED_EMAIL].
2. Values of secret-named keys (DB_PASS=..., "apiKey": "...") whatever they look like, then a sweep for long
   random-looking tokens the rules don't know (unknown providers, random passwords, letters-only tokens).
3. A final guard on the fully assembled request (`guard_payload`): the same checks run once more over the exact
   bytes about to be sent, so nothing that bypassed a caller's redaction can leave the server.

Model output goes through the same functions, so a model that echoes or invents a key never shows one in the UI.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..detection.engine import scan_text, shannon_entropy

PLACEHOLDER_RE = re.compile(r"\[REDACTED(?::[a-z0-9_]+|_[A-Z_]+)?\]")
# Long runs of key-like characters. Hex digests and UUID-ish strings are included on purpose: inside a request to an
# external service, an unexplained random string is treated as sensitive.
# "=" only as trailing base64 padding, so NAME=value splits into the name and the value.
TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_\-+/])[A-Za-z0-9_\-+/]{24,}={0,2}(?![A-Za-z0-9_\-+/=])")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
URL_CREDS_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)([^\s:/@'\"]+):([^\s@/'\"]+)@")
ENTROPY_THRESHOLD = 4.0
LETTERS_ENTROPY_THRESHOLD = 4.2
SEPARATED_WORDS_RE = re.compile(r"^[A-Za-z]+(?:[_-][A-Za-z]+)+$")  # some_long_snake_case or kebab-case-name
VOWELS = set("aeiouAEIOU")

# Values of keys that name a secret (DB_PASS=..., "apiKey": "...", token: ...) are redacted whatever they look like.
_KEY = (r"[A-Za-z0-9_.\-]*(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_\-]?key|apikey|private[_\-]?key|auth(?!or)|"
        r"credential|access[_\-]?key|signing[_\-]?key|encryption[_\-]?key|session[_\-]?key|salt)[A-Za-z0-9_.\-]*")
QUOTED_VALUE_RE = re.compile(rf"(?i)(\b{_KEY}['\"]?\s*(?:[:=]|=>)\s*)(['\"])([^'\"\n]{{4,512}})\2")
LINE_VALUE_RE = re.compile(rf"(?im)^([ \t]*(?:export[ \t]+)?['\"]?{_KEY}['\"]?[ \t]*[:=][ \t]*)(?!['\"])([^\n#]*?)[ \t]*(?=#|\r?$)")
CODE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".go", ".rb", ".php", ".cs", ".rs", ".kt", ".swift", ".c",
            ".cc", ".cpp", ".h", ".scala", ".lua", ".pl", ".dart", ".vue", ".svelte"}
SAFE_VALUES = {"true", "false", "null", "none", "nil", "yes", "no", "on", "off", "required", "optional"}


def _is_random(token: str) -> bool:
    if PLACEHOLDER_RE.fullmatch(token) or SEPARATED_WORDS_RE.match(token):
        return False
    has_digit = any(c.isdigit() for c in token)
    has_alpha = any(c.isalpha() for c in token)
    entropy = shannon_entropy(token)
    if has_digit and has_alpha:
        return entropy >= ENTROPY_THRESHOLD
    if token.isalpha():
        # Letters only (e.g. jCLSbRdIGWmLTukeQvFI...): random strings flip case constantly and have few vowels;
        # camelCase identifiers like XMLHttpRequestEventTarget do not, and stay below the entropy bar.
        flips = sum(1 for a, b in zip(token, token[1:]) if a.isupper() != b.isupper()) / (len(token) - 1)
        vowels = sum(c in VOWELS for c in token) / len(token)
        return entropy >= LETTERS_ENTROPY_THRESHOLD and (flips >= 0.45 or vowels < 0.25)
    return False


def _keep_value(key: str, value: str) -> bool:
    """True when a sensitive-looking key's value is clearly not a secret (references, flags, short numbers)."""
    v = value.strip().strip("'\"")
    low = key.lower()
    return (
        len(v) < 4 or "[REDACTED" in v or v.startswith(("$", "%", "{{", "<")) or v.lower() in SAFE_VALUES
        or (v.isdigit() and len(v) <= 6) or any(x in v for x in ("process.env", "os.environ", "getenv", "import.meta.env"))
        or "public" in low or "publishable" in low
    )


def _is_code_path(path: str | None) -> bool:
    name = (path or "").rsplit("/", 1)[-1]
    return "." in name and "." + name.rsplit(".", 1)[-1].lower() in CODE_EXT


def redact_text(text: str | None, path: str | None = None) -> tuple[str, int]:
    """Return (redacted_text, number_of_redactions)."""
    if not text:
        return text or "", 0
    count = 0

    # 1. Detection engine: replace match spans right-to-left so offsets stay valid.
    spans = sorted(((m.start, m.end, m.rule.id, m.rule.category) for m in scan_text(text, path)), key=lambda t: t[0], reverse=True)
    out = text
    last_start = len(text) + 1
    for start, end, rule_id, category in spans:
        if end > last_start:  # overlapping span already replaced
            continue
        label = "[REDACTED_EMAIL]" if category == "email" else f"[REDACTED:{rule_id}]"
        out = out[:start] + label + out[end:]
        last_start = start
        count += 1

    # 2. Values of secret-named keys. Quoted values anywhere; unquoted NAME=value lines only outside source code
    #    (.env, YAML, INI, properties, shell), where they are literals rather than expressions.
    def _quoted(m: re.Match) -> str:
        nonlocal count
        if _keep_value(m.group(1), m.group(3)):
            return m.group(0)
        count += 1
        return f"{m.group(1)}{m.group(2)}[REDACTED:secret_value]{m.group(2)}"

    out = QUOTED_VALUE_RE.sub(_quoted, out)
    if not _is_code_path(path):
        def _line(m: re.Match) -> str:
            nonlocal count
            if not m.group(2) or _keep_value(m.group(1), m.group(2)):
                return m.group(0)
            count += 1
            return f"{m.group(1)}[REDACTED:secret_value]"

        out = LINE_VALUE_RE.sub(_line, out)

    # 3. Credentials embedded in URLs the rules may not cover (scheme://user:pass@host).
    out, n = URL_CREDS_RE.subn(lambda m: f"{m.group(1)}{m.group(2)}:[REDACTED:url_password]@", out)
    count += n

    # 4. Any remaining email address.
    out, n = EMAIL_RE.subn("[REDACTED_EMAIL]", out)
    count += n

    # 5. Unknown high-entropy tokens (letters-only ones included).
    def _sweep(m: re.Match) -> str:
        nonlocal count
        tok = m.group(0)
        if _is_random(tok):
            count += 1
            return "[REDACTED_HIGH_ENTROPY]"
        return tok

    out = TOKEN_RE.sub(_sweep, out)
    return out, count


def redact_obj(obj: Any, path: str | None = None) -> tuple[Any, int]:
    """Recursively redact every string inside dicts/lists. Returns (new_obj, redactions)."""
    if isinstance(obj, str):
        return redact_text(obj, path)
    if isinstance(obj, list):
        total, items = 0, []
        for item in obj:
            v, n = redact_obj(item, path)
            items.append(v)
            total += n
        return items, total
    if isinstance(obj, dict):
        total, out = 0, {}
        for k, v in obj.items():
            nv, n = redact_obj(v, path)
            out[k] = nv
            total += n
        return out, total
    return obj, 0


def leaks(text: str) -> list[str]:
    """Rule ids (or 'high_entropy') of anything secret-like still present. Empty means safe to send."""
    found = [m.rule.id for m in scan_text(text) if not m.placeholder and m.rule.category != "email"]
    found += ["high_entropy" for m in TOKEN_RE.finditer(text) if _is_random(m.group(0))]
    return found


def guard_payload(messages: list[dict]) -> tuple[list[dict], int]:
    """Final check on the exact messages about to be sent. Redacts anything left and reports how much it caught."""
    total = 0
    safe = []
    for msg in messages:
        content, n = redact_text(msg.get("content", ""))
        total += n
        safe.append({**msg, "content": content})
    # Belt and braces: the serialized payload must now be clean.
    remaining = leaks(json.dumps(safe))
    if remaining:
        raise RuntimeError(f"Refusing to send: unredacted secret-like content remains ({', '.join(sorted(set(remaining)))})")
    return safe, total
