"""CVSS v3.1 base score calculation.

Findings carry a vector; the score and the severity band are derived from it so
the three can never disagree.
"""

from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def _roundup(value: float) -> float:
    """Round up to one decimal, as defined in the CVSS v3.1 specification."""
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    parts = vector.split("/")
    if not parts or parts[0] not in ("CVSS:3.1", "CVSS:3.0"):
        raise ValueError(f"not a CVSS v3 vector: {vector!r}")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, sep, value = part.partition(":")
        if not sep or key in metrics:
            raise ValueError(f"malformed CVSS vector: {vector!r}")
        metrics[key] = value
    missing = [key for key in _REQUIRED if key not in metrics]
    if missing:
        raise ValueError(f"CVSS vector {vector!r} is missing {', '.join(missing)}")
    return metrics


def base_score(vector: str) -> float:
    """Return the CVSS v3.1 base score for ``vector``."""
    m = parse_vector(vector)
    try:
        changed = {"U": False, "C": True}[m["S"]]
        pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[m["PR"]]
        exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
    except KeyError as exc:
        raise ValueError(f"invalid metric value in CVSS vector {vector!r}") from exc

    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    if changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def rating(score: float) -> str:
    """Qualitative severity rating for a base score."""
    if score == 0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"
