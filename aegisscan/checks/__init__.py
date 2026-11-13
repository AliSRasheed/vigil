"""Checks. One module per check; modules in this package are discovered automatically."""

from aegisscan.checks.base import Check, CheckSkipped, discover_checks

__all__ = ["Check", "CheckSkipped", "discover_checks"]
