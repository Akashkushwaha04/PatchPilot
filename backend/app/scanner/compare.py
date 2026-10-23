"""Compare findings between an original scan and a rescan.

Matching strategy, applied in order, each finding matched at most once:
  1. Exact fingerprint: same rule ID + normalized file path + normalized (masked) line text.
     Survives code moving up or down in the file.
  2. Location: same rule ID + same file + line within ±LINE_WINDOW of the original.
     Catches the same issue on a line whose text was lightly edited.
Anything in the original that is not matched is "resolved / no longer detected".
Anything in the rescan that is not matched is "newly introduced".
"""
from __future__ import annotations

LINE_WINDOW = 8


def compare_findings(before: list[dict], after: list[dict]) -> dict:
    remaining: list[dict] = []
    unmatched_after = list(after)
    unmatched_before: list[dict] = []

    by_fp: dict[str, list[dict]] = {}
    for a in unmatched_after:
        by_fp.setdefault(a["fingerprint"], []).append(a)

    pending = []
    for b in before:
        cands = by_fp.get(b["fingerprint"])
        if cands:
            a = cands.pop(0)
            unmatched_after.remove(a)
            remaining.append(_pair(b, a, "fingerprint"))
        else:
            pending.append(b)

    for b in pending:
        best, best_d = None, None
        for a in unmatched_after:
            if a["rule_id"] == b["rule_id"] and a["file"].lower() == b["file"].lower():
                d = abs(a["line"] - b["line"])
                if d <= LINE_WINDOW and (best_d is None or d < best_d):
                    best, best_d = a, d
        if best is not None:
            unmatched_after.remove(best)
            remaining.append(_pair(b, best, "location"))
        else:
            unmatched_before.append(b)

    resolved = [{
        "before": b,
        "verification": (
            f"Rule {b['rule_id']} no longer matches in {b['file']}: no finding with the same fingerprint, "
            f"and no {b['rule_id']} finding within ±{LINE_WINDOW} lines of line {b['line']} in the new version."
        ),
    } for b in unmatched_before]

    severity_changes = [r for r in remaining if r["before"]["severity"] != r["after"]["severity"]]
    return {
        "resolved": resolved,
        "remaining": remaining,
        "new": unmatched_after,
        "severity_changes": severity_changes,
        "method": "Matched by rule ID + file path + normalized line text, then by rule ID + file + nearby line (±%d)." % LINE_WINDOW,
    }


def _pair(b: dict, a: dict, how: str) -> dict:
    return {"before": b, "after": a, "matched_by": how}
