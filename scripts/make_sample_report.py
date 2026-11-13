"""Regenerate docs/sample-report.html and docs/sample-report.json.

Starts the deliberately vulnerable fixture app over HTTPS on localhost and scans it
with the real CLI. Run from the repository root:

    python scripts/make_sample_report.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests.fixtures.app import FixtureApp  # noqa: E402
from tests.fixtures.certs import make_tls_material  # noqa: E402

PORT = 8443


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="aegisscan-sample-"))
    material = make_tls_material(work / "tls")
    app = FixtureApp("vulnerable", tls=material.vulnerable, port=PORT, public_host="localhost")
    app.start()
    try:
        command = [
            sys.executable, "-m", "aegisscan.cli", "scan", app.url,
            "--output", str(work / "out"), "--ca-bundle", str(material.ca_file),
        ]  # fmt: skip
        completed = subprocess.run(command, cwd=ROOT, check=False)
    finally:
        app.stop()
    if completed.returncode != 0:
        return completed.returncode
    docs = ROOT / "docs"
    docs.mkdir(exist_ok=True)
    for suffix in ("html", "json"):
        shutil.copyfile(
            work / "out" / f"aegisscan-report.{suffix}", docs / f"sample-report.{suffix}"
        )
        print(f"wrote docs/sample-report.{suffix}")
    shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
