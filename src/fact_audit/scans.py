"""Run the audit stages for the desktop UI and write the reports next to the project."""

import contextlib
import io
from pathlib import Path

from .audit import run_audit
from .engines.deps import load_config, scan
from .engines.feeds import enrich
from .report_deps import render


def run_scans(
    target: Path,
    *,
    opengrep: bool = True,
    diff: bool = False,
    deps: bool = True,
    online: bool = False,
    log=print,
) -> list[Path]:
    """Run the selected stages against `target` and write the reports next to it."""
    if not target.is_dir():
        raise ValueError(f"not a directory: {target}")

    written: list[Path] = []
    if opengrep:
        result = _stage(
            log,
            "Running Opengrep...",
            lambda: run_audit(str(target), max_findings=50, baseline="HEAD" if diff else None),
        )
        if result is not None:
            report, _ = result
            output = target / "report.md"
            output.write_text(report, encoding="utf-8")
            written.append(output)
            log(f"Wrote {output}")

    if deps:
        result = _stage(log, "Scanning dependencies...", lambda: _deps_scan(target, online))
        if result is not None:
            output = target / "deps-report.md"
            output.write_text(render(result), encoding="utf-8")
            written.append(output)
            log(f"Wrote {output}")

    return written


def _deps_scan(target: Path, online: bool):
    config = load_config(target)
    config.online = online
    result = scan(str(target), config)
    if online:
        enrich(result)
    return result


def _stage(log, label: str, run):
    log(label)
    buffer = io.StringIO()
    try:
        # The engine reports progress on stdout/stderr; surface it in the UI instead.
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            value = run()
    except Exception as exc:
        log(f"{label.rstrip('.')} failed: {exc}")
        return None
    progress = buffer.getvalue().strip()
    if progress:
        log(progress)
    return value
