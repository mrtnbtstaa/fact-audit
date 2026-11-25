"""Findings baselines: persist a scan, then classify new, existing and resolved findings."""

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from fact_audit.engines.git_utils import repository_id
from fact_audit.findings import FINGERPRINT_VERSION, Finding, record

BASELINE_FORMAT = "fact-audit-baseline"
BASELINE_VERSION = 1

NEW = "new"
EXISTING = "existing"
REINTRODUCED = "reintroduced"
GATED_STATUSES = (NEW, REINTRODUCED)


class BaselineError(RuntimeError):
    """The baseline file is missing, corrupt, incompatible or from another repository."""


def baseline_document(
    project_path: str, findings: list[Finding], revision: str | None = None, resolved: list[dict] | None = None
) -> dict:
    unique = {f.fingerprint: f for f in findings}
    return {
        "format": BASELINE_FORMAT,
        "version": BASELINE_VERSION,
        "fingerprint_version": FINGERPRINT_VERSION,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": str(Path(project_path).resolve()),
        "repository": repository_id(project_path),
        "revision": revision,
        "findings": [record(f) for f in unique.values()],
        "resolved": resolved or [],
    }


def load_baseline(path: str | Path, project_path: str) -> dict:
    source = Path(path)
    if not source.is_file():
        raise BaselineError(
            f"baseline not found: {source} (create it with 'fact-audit baseline <path>')"
        )
    try:
        doc = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineError(f"cannot read baseline {source}: {exc}") from exc

    if not isinstance(doc, dict) or doc.get("format") != BASELINE_FORMAT:
        raise BaselineError(f"{source} is not a fact-audit baseline")
    if doc.get("version") != BASELINE_VERSION:
        raise BaselineError(
            f"baseline version {doc.get('version')} is not supported (expected {BASELINE_VERSION}); recreate it"
        )
    if doc.get("fingerprint_version") != FINGERPRINT_VERSION:
        raise BaselineError(
            f"baseline uses fingerprint version {doc.get('fingerprint_version')} "
            f"(expected {FINGERPRINT_VERSION}); recreate it"
        )
    if not isinstance(doc.get("findings"), list) or not isinstance(doc.get("resolved", []), list):
        raise BaselineError(f"{source} is corrupt: findings and resolved must be lists")

    recorded, current = doc.get("repository"), repository_id(project_path)
    if recorded and current and recorded != current:
        raise BaselineError(f"baseline belongs to {recorded}, not {current}")
    return doc


@dataclass
class Comparison:
    status: dict[str, str]  # fingerprint -> new | existing | reintroduced
    resolved: list[dict]  # baseline records no longer detected


def compare(findings: list[Finding], baseline: dict) -> Comparison:
    known = {r.get("fingerprint") for r in baseline["findings"]}
    was_resolved = {r.get("fingerprint") for r in baseline.get("resolved") or []}
    status = {}
    for finding in findings:
        if finding.fingerprint in was_resolved:
            status[finding.fingerprint] = REINTRODUCED
        elif finding.fingerprint in known:
            status[finding.fingerprint] = EXISTING
        else:
            status[finding.fingerprint] = NEW
    current = {f.fingerprint for f in findings}
    resolved = [r for r in baseline["findings"] if r.get("fingerprint") not in current]
    return Comparison(status, resolved)


def updated_baseline(
    project_path: str,
    findings: list[Finding],
    baseline: dict,
    revision: str | None,
    partial: bool = False,
) -> dict:
    """Roll the baseline forward, keeping earlier resolved findings for reintroduction.

    A diff-scoped scan only covers changed files, so it may add findings but never
    resolve or drop one.
    """
    if partial:
        records = {r.get("fingerprint"): r for r in baseline["findings"]}
        records.update({f.fingerprint: record(f) for f in findings})
        doc = baseline_document(project_path, [], revision, baseline.get("resolved") or [])
        doc["findings"] = list(records.values())
        return doc

    current = {f.fingerprint for f in findings}
    carried = [
        r
        for r in (baseline.get("resolved") or []) + baseline["findings"]
        if r.get("fingerprint") not in current
    ]
    resolved, seen = [], set()
    for item in carried:
        key = item.get("fingerprint")
        if key and key not in seen:
            seen.add(key)
            resolved.append(item)
    return baseline_document(project_path, findings, revision, resolved)


def save_baseline(path: str | Path, doc: dict) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, target)  # atomic: a failed write never leaves a half-valid baseline
