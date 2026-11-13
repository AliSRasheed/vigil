"""Check base class and registry.

A check is a plugin: a class with metadata and an async ``run``. Subclassing
`Check` registers it; `discover_checks()` imports every module under
``aegisscan.checks`` so that dropping a new module into the package is all it
takes to add a check. The engine never refers to an individual check.
"""

from __future__ import annotations

import importlib
import pkgutil
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar

from aegisscan import cvss
from aegisscan.models import CheckInfo, Evidence, Finding, Severity, Target

if TYPE_CHECKING:
    from aegisscan.engine import ScanContext

_REGISTRY: dict[str, type[Check]] = {}
_REQUIRED = ("id", "title", "severity", "cwe", "owasp", "category")
CATEGORIES = ("recon", "config", "injection")


class CheckSkipped(Exception):  # noqa: N818 - control flow, not an error
    """Raised by a check that does not apply to the target. The reason is reported."""


class Check(ABC):
    id: ClassVar[str]
    title: ClassVar[str]
    severity: ClassVar[Severity]  # highest severity this check can report
    cwe: ClassVar[str]
    owasp: ClassVar[str]
    category: ClassVar[str]
    safe: ClassVar[bool] = True  # sends only benign, read-only probes
    description: ClassVar[str] = ""

    def __init_subclass__(cls, register: bool = True, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        if not register:
            return
        missing = [name for name in _REQUIRED if not hasattr(cls, name)]
        if missing:
            raise TypeError(f"check {cls.__name__} is missing metadata: {', '.join(missing)}")
        if cls.category not in CATEGORIES:
            raise TypeError(f"check {cls.id}: unknown category {cls.category!r}")
        existing = _REGISTRY.get(cls.id)
        if existing is not None and existing.__qualname__ != cls.__qualname__:
            raise TypeError(f"duplicate check id {cls.id!r}")
        _REGISTRY[cls.id] = cls

    @classmethod
    def info(cls) -> CheckInfo:
        return CheckInfo(
            id=cls.id,
            title=cls.title,
            category=cls.category,
            severity=cls.severity,
            cwe=cls.cwe,
            owasp=cls.owasp,
            safe=cls.safe,
            description=cls.description,
        )

    @abstractmethod
    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        """Probe the target and return findings (an empty list when there is nothing)."""

    def finding(
        self,
        *,
        title: str,
        url: str,
        description: str,
        why: str,
        evidence: list[Evidence],
        remediation: str,
        cvss_vector: str | None = None,
        severity: Severity | None = None,
        cwe: str | None = None,
        owasp: str | None = None,
        references: list[str] | None = None,
    ) -> Finding:
        """Build a finding. With a CVSS vector, score and severity are derived from it."""
        score: float | None = None
        if cvss_vector is not None:
            score = cvss.base_score(cvss_vector)
            severity = Severity(cvss.rating(score))
        elif severity is None:
            severity = Severity.INFO
        return Finding(
            id=Finding.make_id(self.id, url, title),
            check_id=self.id,
            title=title,
            severity=severity,
            category=self.category,
            url=url,
            description=description,
            why=why,
            evidence=evidence,
            remediation=remediation,
            cwe=cwe or self.cwe,
            owasp=owasp or self.owasp,
            cvss_vector=cvss_vector,
            cvss_score=score,
            references=references or [],
        )


def discover_checks() -> list[type[Check]]:
    """Import every module under ``aegisscan.checks`` and return the registered checks."""
    import aegisscan.checks as package

    for module in pkgutil.walk_packages(package.__path__, prefix=f"{package.__name__}."):
        importlib.import_module(module.name)
    order = {category: index for index, category in enumerate(CATEGORIES)}
    return sorted(_REGISTRY.values(), key=lambda check: (order[check.category], check.id))
