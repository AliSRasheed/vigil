"""Report renderers."""

from __future__ import annotations

from pathlib import Path

from aegisscan.models import ScanResult

FORMATS = ("json",)


def render_json(result: ScanResult) -> str:
    """Machine-readable export of the whole scan."""
    return result.model_dump_json(indent=2) + "\n"


def load_result(path: Path) -> ScanResult:
    return ScanResult.model_validate_json(Path(path).read_text(encoding="utf-8"))


_RENDERERS = {"json": render_json}


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
