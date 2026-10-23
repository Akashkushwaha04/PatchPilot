"""Security score.

Method (also shown in the UI):
  penalty = Σ per-finding penalty
  score   = 100 × 60 / (60 + penalty)      (diminishing returns: never below 0,
                                            and large projects stay comparable)
  per-finding penalty = severity weight × confidence factor
    severity weights:  critical 25, high 12, medium 5, low 2, info 0
    confidence factor: high 1.0, medium 0.7, low 0.4
  Repeats of the same rule are capped at 2× that rule's single-finding weight,
  so one noisy rule cannot dominate the score.
  Findings marked "Accepted risk" still count; only a verified rescan removes them.

A high score means few known patterns were detected. It is not proof of safety.
"""
from __future__ import annotations

from collections import defaultdict

SEVERITY_WEIGHT = {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}
CONFIDENCE_FACTOR = {"high": 1.0, "medium": 0.7, "low": 0.4}

METHOD = (
    "Each finding adds a penalty of severity weight (critical 25, high 12, medium 5, low 2) "
    "× confidence (high 1.0, medium 0.7, low 0.4); repeats of one rule are capped at 2× its weight. "
    "Score = 100 × 60 ÷ (60 + total penalty), so one critical issue gives about 71 and a clean scan gives 100. "
    "The score reflects detected patterns only and is not a guarantee of security."
)
K = 60


def compute_score(findings: list[dict]) -> dict:
    per_rule: dict[str, list[float]] = defaultdict(list)
    for f in findings:
        per_rule[f["rule_id"]].append(SEVERITY_WEIGHT[f["severity"]] * CONFIDENCE_FACTOR[f["confidence"]])
    total = 0.0
    for penalties in per_rule.values():
        cap = 2 * max(penalties) if penalties else 0
        total += min(sum(penalties), cap)
    score = round(100 * K / (K + total))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    return {"score": score, "grade": grade, "penalty": round(total, 1), "method": METHOD}


def severity_counts(findings: list[dict]) -> dict:
    counts = {k: 0 for k in SEVERITY_WEIGHT}
    for f in findings:
        counts[f["severity"]] += 1
    return counts
