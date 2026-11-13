"""Command line interface: scan, list-checks, report."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Annotated

import typer

from vigil import __version__, report
from vigil.checks.base import discover_checks
from vigil.engine import ScanOptions, run_scan, select_checks
from vigil.models import ScanResult, Severity
from vigil.scope import ENV_VAR, FLAG, Permit, ScopeError, authorize

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Vigil: web application security scanner for authorized testing.",
)

EXIT_BLOCKED = 2
_SEVERITY_COLORS = {
    Severity.CRITICAL: typer.colors.MAGENTA,
    Severity.HIGH: typer.colors.RED,
    Severity.MEDIUM: typer.colors.YELLOW,
    Severity.LOW: typer.colors.BLUE,
    Severity.INFO: typer.colors.WHITE,
}


class _EchoHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        typer.echo(self.format(record), err=True)


def _configure_logging(verbose: bool) -> None:
    handler = _EchoHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(name)s: %(message)s", "%H:%M:%S"))
    root = logging.getLogger("vigil")
    root.handlers = [handler]
    root.setLevel(logging.INFO)
    logging.getLogger("vigil.engine").setLevel(logging.INFO if verbose else logging.WARNING)


def _split(value: str | None) -> list[str] | None:
    if value is None:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


def _write_audit_line(directory: Path, permit: Permit) -> Path:
    """Append the authorization assertion to the audit trail next to the reports."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "audit.log"
    record = permit.authorization
    entry = {
        "timestamp": record.timestamp.isoformat(timespec="seconds"),
        "target": permit.target.url,
        "scope": sorted(permit.scope.hosts),
        "include_subdomains": permit.scope.include_subdomains,
        "authorization_method": record.method,
        "authorization": record.summary(),
        "tool_version": __version__,
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")
    return path


def _print_summary(result: ScanResult) -> None:
    ran = sum(1 for run in result.checks if run.status == "ran")
    skipped = sum(1 for run in result.checks if run.status == "skipped")
    errors = sum(1 for run in result.checks if run.status == "error")
    typer.echo("")
    typer.echo(f"Target         {result.target.url}")
    typer.echo(f"Authorization  {result.authorization.summary()}")
    typer.echo(
        f"Checks         {ran} ran, {skipped} not applicable, {errors} failed; "
        f"{result.requests_sent} requests in {result.duration_seconds}s"
    )
    counts = ", ".join(f"{count} {name}" for name, count in result.severity_counts().items())
    typer.echo(f"Findings       {len(result.findings)} ({counts})")
    typer.echo("")
    for finding in result.findings:
        label = typer.style(
            f"{finding.severity.value.upper():<8}", fg=_SEVERITY_COLORS[finding.severity], bold=True
        )
        typer.echo(f"  {label} {finding.title}  [{finding.check_id}]")
    for run in result.checks:
        if run.status == "error":
            typer.echo(f"  check {run.check.id} failed: {run.detail}", err=True)
    if result.out_of_scope:
        hosts = sorted({record.host for record in result.out_of_scope if record.host})
        typer.echo("")
        typer.echo(f"Out of scope, recorded and not contacted: {', '.join(hosts)}")


@app.command()
def scan(
    target: Annotated[
        str,
        typer.Argument(help="URL to scan, e.g. https://app.example.com. Its host is the scope."),
    ],
    scope: Annotated[
        Path | None,
        typer.Option(
            "--scope",
            help="Optional scope.yaml: extra hosts, include_subdomains, exclude_paths, "
            "authorization block.",
        ),
    ] = None,
    i_have_authorization: Annotated[
        bool,
        typer.Option(
            FLAG,
            help="Assert that you own the target or hold written permission to test it. "
            f"({ENV_VAR}=1 or a scope-file authorization block also count.)",
        ),
    ] = False,
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Directory for the reports and audit log.")
    ] = Path("vigil-out"),
    formats: Annotated[
        str, typer.Option("--format", help=f"Report formats, comma separated: {report.FORMATS}.")
    ] = ",".join(report.FORMATS),
    checks: Annotated[
        str | None, typer.Option("--checks", help="Only run these check ids or categories.")
    ] = None,
    skip: Annotated[
        str | None, typer.Option("--skip", help="Skip these check ids or categories.")
    ] = None,
    rate: Annotated[
        float, typer.Option("--rate", min=0.1, max=50.0, help="Max requests per second per host.")
    ] = 5.0,
    concurrency: Annotated[
        int, typer.Option("--concurrency", min=1, max=20, help="Max simultaneous requests.")
    ] = 5,
    timeout: Annotated[
        float, typer.Option("--timeout", min=1.0, max=120.0, help="Per-request timeout, seconds.")
    ] = 10.0,
    ca_bundle: Annotated[
        Path | None,
        typer.Option("--ca-bundle", help="Extra CA certificates (PEM) trusted by the TLS check."),
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Log each check.")] = False,
) -> None:
    """Scan one target. Only the named host is ever contacted."""
    _configure_logging(verbose)
    try:
        permit = authorize(target, scope_file=scope, flag=i_have_authorization)
    except ScopeError as exc:
        typer.secho(f"Scan blocked: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_BLOCKED) from exc

    try:
        selected = select_checks(only=_split(checks), skip=_split(skip))
        format_list = _split(formats) or []
        unknown = [name for name in format_list if name not in report.FORMATS]
        if unknown:
            raise ValueError(f"unknown report format: {', '.join(unknown)}")
    except ValueError as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_BLOCKED) from exc

    audit_path = _write_audit_line(output, permit)
    options = ScanOptions(rate=rate, concurrency=concurrency, timeout=timeout, ca_file=ca_bundle)
    result = asyncio.run(run_scan(permit, checks=selected, options=options))

    _print_summary(result)
    typer.echo("")
    for path in report.write_reports(result, output, format_list):
        typer.echo(f"Report written: {path}")
    typer.echo(f"Audit log:      {audit_path}")


def checks_markdown() -> str:
    """The check table, as kept in the README."""
    lines = [
        "| ID | Check | Category | Max severity | CWE | OWASP Top 10:2025 |",
        "|---|---|---|---|---|---|",
    ]
    for check in discover_checks():
        lines.append(
            f"| `{check.id}` | {check.title} | {check.category} | {check.severity.value} "
            f"| {check.cwe} | {check.owasp} |"
        )
    return "\n".join(lines)


@app.command("list-checks")
def list_checks(
    markdown: Annotated[
        bool, typer.Option("--markdown", help="Print the table used in the README.")
    ] = False,
) -> None:
    """List the registered checks."""
    if markdown:
        typer.echo(checks_markdown())
        return
    registered = discover_checks()
    if not registered:
        typer.echo("No checks registered.")
        return
    width = max(len(check.id) for check in registered)
    for check in registered:
        typer.echo(
            f"{check.id:<{width}}  {check.severity.value:<8}  {check.category:<9}  {check.title}"
        )


@app.command("report")
def render_report(
    source: Annotated[Path, typer.Argument(help="JSON report written by `vigil scan`.")],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="File to write (default: beside the JSON file)."),
    ] = None,
    fmt: Annotated[str, typer.Option("--format", help="html or json.")] = "html",
) -> None:
    """Re-render a report from a JSON export, without scanning again."""
    if fmt not in report.FORMATS:
        typer.secho(f"Error: unknown report format: {fmt}", fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_BLOCKED)
    try:
        result = report.load_result(source)
    except (OSError, ValueError) as exc:
        typer.secho(f"Error: cannot read {source}: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_BLOCKED) from exc
    renderer = report.render_html if fmt == "html" else report.render_json
    destination = output or source.with_suffix(f".{fmt}")
    destination.write_text(renderer(result), encoding="utf-8")
    typer.echo(f"Report written: {destination}")


@app.callback(invoke_without_command=True)
def main(
    version: Annotated[
        bool, typer.Option("--version", help="Show the version and exit.", is_eager=True)
    ] = False,
) -> None:
    if version:
        typer.echo(f"Vigil {__version__}")
        raise typer.Exit()


if __name__ == "__main__":
    app()
