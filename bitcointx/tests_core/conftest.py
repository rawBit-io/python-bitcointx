"""Pytest plugin that writes a short test summary into this directory."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import List

import pytest


_RESULT_PATH = Path(__file__).with_name("script_vector_results.txt")


@pytest.hookimpl(tryfirst=True)
def pytest_terminal_summary(terminalreporter, exitstatus: int) -> None:
    """Write a minimal summary for every pytest run."""
    stats = terminalreporter.stats
    summary: List[str] = []

    summary.append(f"timestamp_utc={datetime.utcnow().isoformat()}Z")
    summary.append(f"collected={terminalreporter._numcollected}")  # type: ignore[attr-defined]
    summary.append(f"passed={len(stats.get('passed', []))}")
    summary.append(f"failed={len(stats.get('failed', []))}")
    summary.append(f"skipped={len(stats.get('skipped', []))}")
    summary.append(f"xfail={len(stats.get('xfailed', []))}")
    summary.append(f"xpass={len(stats.get('xpassed', []))}")
    summary.append(f"exitstatus={exitstatus}")

    failed = stats.get("failed", [])
    if failed:
        summary.append("")
        summary.append("failed_tests:")
        summary.extend(f"- {rep.nodeid}" for rep in failed)

    _RESULT_PATH.write_text("\n".join(summary))
