"""AI risk scoring: model confidence that a hit is a real secret, combined with impact and exposure."""

import tempfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import joblib
import numpy as np

from .features import FindingContext, extract

MODEL_PATH = Path(__file__).with_name("model.joblib")
IMPACT = {"critical": 1.0, "high": 0.8, "medium": 0.55, "low": 0.25}


@dataclass
class Score:
    confidence: float
    risk: float
    severity: str
    factors: list[str]


@lru_cache
def _model():
    if MODEL_PATH.exists():
        return joblib.load(MODEL_PATH)
    from .train import train_and_save

    # The model is normally trained at build time. If it is missing, train it now; serverless filesystems are
    # read-only apart from /tmp, so fall back there when the package directory can't be written.
    for path in (MODEL_PATH, Path(tempfile.gettempdir()) / "ghosttrace-model.joblib"):
        if path.exists():
            return joblib.load(path)
        try:
            train_and_save(path, verbose=False)
            return joblib.load(path)
        except OSError:
            continue
    raise RuntimeError("Could not train or load the risk model")


def severity_for(risk: float) -> str:
    if risk >= 75:
        return "critical"
    if risk >= 55:
        return "high"
    if risk >= 30:
        return "medium"
    return "low"


def score_all(items: list[tuple[FindingContext, str, str | None, str]]) -> list[Score]:
    """Score (context, rule name, file path, source) tuples with one model call; per-row calls are ~100x slower."""
    if not items:
        return []
    probs = _model().predict_proba(np.array([extract(ctx) for ctx, *_ in items]))[:, 1]
    return [_score(ctx, rule_name, file_path, source, float(p)) for (ctx, rule_name, file_path, source), p in zip(items, probs)]


def _score(ctx: FindingContext, rule_name: str, file_path: str | None, source: str, confidence: float) -> Score:
    exposure = 1.0 if ctx.public else 0.75
    if source in ("text", "file"):
        exposure = 0.8
    if ctx.history_only:
        exposure *= 0.85
    if ctx.sensitive_path:
        exposure = min(1.0, exposure + 0.05)
    if ctx.test_path:
        exposure *= 0.6  # test fixtures, examples and docs rarely hold live credentials

    if ctx.test_path:
        exposure *= 0.5  # fixtures, tests and docs rarely hold live credentials
    risk = 100 * (confidence ** 0.8) * IMPACT.get(ctx.base_severity, 0.4) * exposure
    risk = round(max(0.0, min(100.0, risk)), 1)

    factors: list[str] = []
    factors.append(f"{'Provider-specific format' if ctx.specific else 'Generic pattern'}: {rule_name}")
    if ctx.category != "email":
        if ctx.entropy >= 4.0:
            factors.append(f"High randomness ({ctx.entropy:.1f} bits/char), typical of real keys")
        elif ctx.entropy < 3.0:
            factors.append(f"Low randomness ({ctx.entropy:.1f} bits/char)")
    if ctx.placeholder:
        factors.append("Looks like a placeholder or variable reference")
    if ctx.test_path:
        factors.append("Located in a test, example or docs path")
    if ctx.sensitive_path and file_path:
        factors.append(f"Committed in a sensitive file ({file_path.split('/')[-1]})")
    if ctx.history_only:
        factors.append("Removed from the latest code but still in git history")
    if source == "github":
        factors.append("Public repository" if ctx.public else "Private repository")
    factors.append(f"AI confidence it is a real secret: {round(confidence * 100)}%")
    return Score(confidence=round(confidence, 4), risk=risk, severity=severity_for(risk), factors=factors)
