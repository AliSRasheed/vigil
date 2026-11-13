"""Target parsing and CVSS scoring."""

from __future__ import annotations

import pytest

from vigil import cvss
from vigil.models import Severity, Target


@pytest.mark.parametrize(
    ("vector", "score", "rating"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "medium"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "high"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "medium"),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1, "low"),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9, "critical"),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0, "info"),
    ],
)
def test_cvss_base_scores_match_the_specification(vector: str, score: float, rating: str) -> None:
    assert cvss.base_score(vector) == score
    assert cvss.rating(score) == rating


@pytest.mark.parametrize(
    "vector",
    ["AV:N/AC:L", "CVSS:3.1/AV:N/AC:L", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", ""],
)
def test_malformed_cvss_vectors_are_rejected(vector: str) -> None:
    with pytest.raises(ValueError):
        cvss.base_score(vector)


def test_severity_ordering() -> None:
    ranked = sorted(Severity, key=lambda severity: severity.rank)
    assert [s.value for s in ranked] == ["info", "low", "medium", "high", "critical"]


def test_target_parsing() -> None:
    target = Target.parse("HTTPS://App.Example.com")
    assert (target.scheme, target.host, target.port, target.path) == (
        "https",
        "app.example.com",
        443,
        "/",
    )
    assert target.url == "https://app.example.com/"
    assert target.origin == "https://app.example.com"

    nested = Target.parse("http://localhost:8080/shop/index.php?id=1")
    assert nested.url == "http://localhost:8080/shop/index.php?id=1"
    assert nested.base_url == "http://localhost:8080/shop/"
    assert nested.join(".git/HEAD") == "http://localhost:8080/shop/.git/HEAD"

    ipv6 = Target.parse("http://[::1]:8000/")
    assert ipv6.host == "::1" and ipv6.origin == "http://[::1]:8000"


@pytest.mark.parametrize("raw", ["app.example.com", "ftp://app.example.com", "https://", ""])
def test_invalid_targets_are_rejected(raw: str) -> None:
    with pytest.raises(ValueError, match="invalid target URL"):
        Target.parse(raw)
