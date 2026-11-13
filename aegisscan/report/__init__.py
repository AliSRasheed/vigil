"""Report renderers: a self-contained HTML report and a JSON export."""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from aegisscan.models import Finding, ScanResult, Severity

FORMATS = ("html", "json")
_SEVERITY_ORDER = [severity.value for severity in reversed(Severity)]  # critical first


def _summary(result: ScanResult) -> dict:
    counts = result.severity_counts()
    highest = next((name for name in _SEVERITY_ORDER if counts[name]), None)
    return {"total": len(result.findings), "by_severity": counts, "highest_severity": highest}


def render_json(result: ScanResult) -> str:
    """Machine-readable export of the whole scan, with a summary block up front."""
    data = result.model_dump(mode="json")
    ordered = {
        "tool": data.pop("tool"),
        "version": data.pop("version"),
        "summary": _summary(result),
        **data,
    }
    return json.dumps(ordered, indent=2) + "\n"


def load_result(path: Path) -> ScanResult:
    """Read a JSON export back, for re-rendering."""
    return ScanResult.model_validate_json(Path(path).read_text(encoding="utf-8"))


def _narrative(result: ScanResult) -> list[str]:
    """Plain-language executive summary, generated from the results."""
    summary = _summary(result)
    counts = summary["by_severity"]
    ran = sum(1 for run in result.checks if run.status == "ran")
    paragraphs = []
    opening = (
        f"AegisScan ran {ran} non-destructive check{'s' if ran != 1 else ''} against "
        f"{result.target.url} on {result.started_at:%d %B %Y}."
    )
    actionable = [name for name in _SEVERITY_ORDER if counts[name] and name != "info"]
    if not result.findings:
        paragraphs.append(f"{opening} No findings were identified by the checks that ran.")
    elif not actionable:
        paragraphs.append(
            f"{opening} No weaknesses were identified; {counts['info']} informational "
            "observation(s) are recorded below."
        )
    else:
        parts = ", ".join(f"{counts[name]} {name}" for name in actionable)
        info = f", plus {counts['info']} informational" if counts["info"] else ""
        paragraphs.append(
            f"{opening} It identified {len(result.findings) - counts['info']} weakness(es): "
            f"{parts}{info}. The highest severity found is {summary['highest_severity']}."
        )
        top = [f.title for f in result.findings if f.severity.rank >= Severity.MEDIUM.rank][:3]
        if top:
            paragraphs.append("Most significant: " + "; ".join(top) + ".")
    not_run = [run for run in result.checks if run.status != "ran"]
    if not_run:
        paragraphs.append(
            f"{len(not_run)} check(s) did not run (not applicable to this target, or failed); "
            "see Checks performed. A clean result covers only the checks listed as run."
        )
    return paragraphs


def render_html(result: ScanResult) -> str:
    """Self-contained HTML report: no scripts, no external resources."""
    environment = Environment(
        loader=PackageLoader("aegisscan", "report/templates"),
        autoescape=select_autoescape(default=True, default_for_string=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    environment.filters["cwe_url"] = _cwe_url
    environment.filters["heading"] = lambda key: str(key).replace("_", " ").capitalize()
    grouped: dict[str, list[Finding]] = {name: [] for name in _SEVERITY_ORDER}
    for finding in result.findings:
        grouped[finding.severity.value].append(finding)
    template = environment.get_template("report.html.j2")
    return template.render(
        result=result,
        summary=_summary(result),
        narrative=_narrative(result),
        grouped={name: items for name, items in grouped.items() if items},
        severities=_SEVERITY_ORDER,
        out_of_scope_hosts=sorted({r.host for r in result.out_of_scope if r.host}),
    )


def _cwe_url(cwe: str | None) -> str | None:
    if cwe and cwe.upper().startswith("CWE-") and cwe[4:].isdigit():
        return f"https://cwe.mitre.org/data/definitions/{cwe[4:]}.html"
    return None


_RENDERERS = {"html": render_html, "json": render_json}


def write_reports(
    result: ScanResult, directory: Path, formats: list[str], stem: str = "aegisscan-report"
) -> list[Path]:
    """Write one file per requested format into ``directory`` and return the paths."""
    unknown = [name for name in formats if name not in _RENDERERS]
    if unknown:
        raise ValueError(
            f"unknown report format: {', '.join(unknown)} (available: {', '.join(_RENDERERS)})"
        )
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for name in formats:
        path = directory / f"{stem}.{name}"
        path.write_text(_RENDERERS[name](result), encoding="utf-8")
        written.append(path)
    return written
