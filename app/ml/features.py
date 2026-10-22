"""Feature extraction shared by training and inference."""

import math
import re
from dataclasses import dataclass

CATEGORIES = ["aws", "cloud", "api_key", "token", "jwt", "private_key", "database", "password", "email", "webhook"]
SEVERITY_NUM = {"low": 0, "medium": 1, "high": 2, "critical": 3}
CONTEXT_RE = re.compile(r"(?i)(secret|token|key|passw|pwd|auth|credential|bearer|private)")

FEATURE_NAMES = (
    ["entropy", "log_length", "placeholder", "test_path", "sensitive_path", "specific_rule", "base_severity",
     "char_classes", "digit_ratio", "unique_ratio", "max_run_ratio", "history_only", "context_keyword", "public_exposure"]
    + [f"cat_{c}" for c in CATEGORIES]
)


@dataclass
class FindingContext:
    category: str
    base_severity: str
    specific: bool
    secret: str
    entropy: float
    placeholder: bool
    test_path: bool
    sensitive_path: bool
    history_only: bool
    line: str
    public: bool


def _max_run(s: str) -> int:
    best = run = 1 if s else 0
    for a, b in zip(s, s[1:]):
        run = run + 1 if a == b else 1
        best = max(best, run)
    return best


def extract(ctx: FindingContext) -> list[float]:
    s = ctx.secret
    n = max(len(s), 1)
    classes = sum([any(c.islower() for c in s), any(c.isupper() for c in s), any(c.isdigit() for c in s), any(not c.isalnum() for c in s)])
    return [
        float(ctx.entropy),
        math.log1p(len(s)),
        float(ctx.placeholder),
        float(ctx.test_path),
        float(ctx.sensitive_path),
        float(ctx.specific),
        float(SEVERITY_NUM.get(ctx.base_severity, 0)),
        float(classes),
        sum(c.isdigit() for c in s) / n,
        len(set(s)) / n,
        _max_run(s) / n,
        float(ctx.history_only),
        float(bool(CONTEXT_RE.search(ctx.line or ""))),
        float(ctx.public),
    ] + [1.0 if ctx.category == c else 0.0 for c in CATEGORIES]
