"""Command line behaviour not covered by the scope gate tests."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from tests.fixtures.app import FixtureApp
from vigil import __version__
from vigil.cli import app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == f"Vigil {__version__}"


def test_list_checks_runs() -> None:
    result = runner.invoke(app, ["list-checks"])
    assert result.exit_code == 0
    markdown = runner.invoke(app, ["list-checks", "--markdown"])
    assert markdown.exit_code == 0
    assert markdown.output.startswith("| ID | Check |")


def test_unknown_check_is_a_usage_error(tmp_path: Path, clean_app: FixtureApp) -> None:
    result = runner.invoke(
        app, ["scan", clean_app.url, "--checks", "no.such.check", "-o", str(tmp_path / "out")]
    )
    assert result.exit_code == 2
    assert "unknown check or category: no.such.check" in result.output
    assert clean_app.requests == []


def test_unknown_report_format_is_a_usage_error(tmp_path: Path, clean_app: FixtureApp) -> None:
    result = runner.invoke(
        app, ["scan", clean_app.url, "--format", "pdf", "-o", str(tmp_path / "out")]
    )
    assert result.exit_code == 2
    assert "unknown report format: pdf" in result.output
