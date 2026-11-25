"""The `fact-audit ci` gate: run both scanners, apply the policy and write the artifacts."""

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from fact_audit.audit import run_audit
from fact_audit.baseline import (
    EXISTING,
    GATED_STATUSES,
    NEW,
    REINTRODUCED,
    BaselineError,
    Comparison,
    compare,
    load_baseline,
    save_baseline,
    updated_baseline,
)
from fact_audit.engines.deps import DepsError, load_config, scan
from fact_audit.engines.feeds import enrich
from fact_audit.engines.git_utils import current_revision
from fact_audit.findings import SEVERITY_ORDER, Finding, csv_text, record
from fact_audit.report_deps import SEVERITY_ORDER as VULN_ORDER
from fact_audit.report_deps import denylisted, write_report

# `error`/`warning`/`info` are the pre-normalization names, kept as aliases.
FAIL_ON_LIMITS = {
    "critical": 0,
    "high": 1,
    "error": 1,
    "medium": 2,
    "warning": 2,
    "low": 3,
    "info": 4,
}
VULN_LIMITS = {"critical": 0, "high": 1, "medium": 2, "low": 3}
ARTIFACTS = ("report.md", "deps-report.md", "fact-audit.sarif", "fact-audit.json", "fact-audit.csv")


@dataclass
class CodeStage:
    findings: list[Finding] = field(default_factory=list)
    status: dict[str, str] = field(default_factory=dict)
    comparison: Comparison | None = None
    failures: list[str] = field(default_factory=list)
    details: list[str] = field(default_factory=list)
    line: str = "failed"
    scanner: str = "failed"
    failed: bool = False


@dataclass
class DepsStage:
    failures: list[str] = field(default_factory=list)
    line: str = "not checked (offline)"
    license_line: str = "not checked (offline)"
    summary: dict = field(
        default_factory=lambda: {"online": False, "vulnerabilities": {}, "denylisted_licenses": 0}
    )
    scanner: str = "not run"
    failed: bool = False


def run_ci_command(argv: list[str]) -> None:
    args = _parse_args(argv)
    _validate(args)
    baseline_doc = _load_baseline(args)

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    revision = current_revision(args.project_path)
    git_base = args.baseline or ("HEAD" if args.diff else None)

    code = _code_stage(args, baseline_doc, git_base, out)
    deps = _deps_stage(args, out)
    failures = code.failures + deps.failures
    failed = code.failed or deps.failed

    if args.update_baseline and not failed:
        failed = not _save_baseline(args, code.findings, baseline_doc, revision, git_base)

    document = _document(args, revision, git_base, code, deps, failures, failed)
    (out / "fact-audit.json").write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    (out / "fact-audit.csv").write_text(csv_text(code.findings, code.status), encoding="utf-8")
    _print_summary(out, code, deps, failures, failed)

    if failed:
        raise SystemExit(3)
    raise SystemExit(1 if failures else 0)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="fact-audit ci", description="Run the code audit and dependency scan as a CI gate"
    )
    parser.add_argument("project_path", help="Path to the project to audit")
    parser.add_argument("--diff", action="store_true", help="Only audit files changed in Git")
    parser.add_argument("--baseline", default=None, help="Git ref to diff against (implies --diff)")
    parser.add_argument(
        "--baseline-file",
        default=None,
        help="Findings baseline to compare against (see 'fact-audit baseline')",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Rewrite the baseline file after a successful run",
    )
    parser.add_argument(
        "--online", action="store_true", help="Check advisories, latest versions and licenses"
    )
    parser.add_argument(
        "--out-dir", default=".", help="Directory for the Markdown, SARIF, JSON and CSV reports"
    )
    parser.add_argument(
        "--no-llm", action="store_true", help="Skip the LLM and write a deterministic report"
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "error", "warning", "info", "none"],
        default="error",
        help="Fail on code findings at or above this severity (default: error = high)",
    )
    parser.add_argument(
        "--fail-on-all", action="store_true", help="Gate every finding, not only new/reintroduced ones"
    )
    parser.add_argument(
        "--max-new",
        type=int,
        default=None,
        help="Fail when more than this many new findings appear (needs --baseline-file)",
    )
    parser.add_argument(
        "--fail-on-vuln", choices=["critical", "high", "medium", "low", "none"], default="high",
        help="Fail on advisories at or above this severity (requires --online)",
    )
    parser.add_argument("--fail-on-license", action="store_true", help="Fail on denylisted licenses")
    return parser.parse_args(argv)


def _validate(args: argparse.Namespace) -> None:
    if not Path(args.project_path).is_dir():
        print(f"error: not a directory: {args.project_path}", file=sys.stderr)
        raise SystemExit(2)
    if (args.max_new is not None or args.update_baseline) and not args.baseline_file:
        print("error: --max-new and --update-baseline require --baseline-file", file=sys.stderr)
        raise SystemExit(2)


def _load_baseline(args: argparse.Namespace) -> dict | None:
    if not args.baseline_file:
        return None
    try:
        return load_baseline(args.baseline_file, args.project_path)
    except BaselineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)


def _code_stage(args, baseline_doc, git_base, out: Path) -> CodeStage:
    stage = CodeStage()
    try:
        report, findings = run_audit(
            args.project_path, 50, git_base, not args.no_llm, str(out / "fact-audit.sarif")
        )
    except Exception as exc:
        print(f"error: code audit failed: {exc}", file=sys.stderr)
        stage.failed = True
        return stage

    stage.findings = findings
    stage.scanner = "ok"
    stage.comparison = compare(findings, baseline_doc) if baseline_doc else None
    if stage.comparison and git_base:
        stage.comparison.resolved = []  # diff-scoped scan: absence proves nothing
    if stage.comparison:
        stage.status = stage.comparison.status
        counts = Counter(stage.status.values())
        report += (
            "\n## Baseline comparison\n\n"
            f"- new: {counts[NEW]}, reintroduced: {counts[REINTRODUCED]}, "
            f"existing: {counts[EXISTING]}, resolved: {len(stage.comparison.resolved)}\n"
        )
    (out / "report.md").write_text(report, encoding="utf-8")
    stage.line = f"{len(findings)} finding(s)"
    if stage.comparison:
        stage.line += f" ({sum(1 for s in stage.status.values() if s in GATED_STATUSES)} new)"
    _gate_code(args, stage)
    return stage


def _gate_code(args, stage: CodeStage) -> None:
    if args.fail_on != "none":
        limit = FAIL_ON_LIMITS[args.fail_on]
        gated = (
            stage.findings
            if args.fail_on_all or not stage.comparison
            else [f for f in stage.findings if stage.status[f.fingerprint] in GATED_STATUSES]
        )
        flagged = [f for f in gated if SEVERITY_ORDER.get(f.severity, 99) <= limit]
        if flagged:
            scope = "new/reintroduced" if stage.comparison and not args.fail_on_all else "all"
            stage.failures.append(
                f"{len(flagged)} {scope} code finding(s) at or above {args.fail_on.upper()}"
            )
            stage.details += [f"    {f.file}:{f.line} {f.rule_id}" for f in flagged[:5]]

    if args.max_new is not None:
        new_count = sum(1 for s in stage.status.values() if s in GATED_STATUSES)
        if new_count > args.max_new:
            stage.failures.append(
                f"{new_count} new/reintroduced finding(s) exceed --max-new {args.max_new}"
            )


def _deps_stage(args, out: Path) -> DepsStage:
    stage = DepsStage()
    try:
        config = load_config(Path(args.project_path), None)
        config.online = config.online or args.online
        result = scan(args.project_path, config)
        if config.online:
            enrich(result)
        write_report(out / "deps-report.md", result)
    except DepsError as exc:
        print(f"error: dependency scan failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
    except Exception as exc:
        print(f"error: dependency scan failed: {exc}", file=sys.stderr)
        stage.failed = True
        return stage

    stage.scanner = "ok"
    deps = [d for m in result.manifests if not m.error for d in m.dependencies]
    counts = Counter(a.severity for d in deps for a in d.advisories)
    denied = [d for d in deps if denylisted(d.license, config.denylist)]
    stage.summary = {
        "online": bool(config.online),
        "vulnerabilities": dict(counts),
        "denylisted_licenses": len(denied),
    }
    if config.online:
        stage.line = (
            ", ".join(
                f"{counts[s]} {s.lower()}"
                for s in sorted(counts, key=lambda s: VULN_ORDER.get(s, 9))
            )
            or "no advisories"
        )
        stage.license_line = f"{len(denied)} denylisted"
        if args.fail_on_vuln != "none":
            limit = VULN_LIMITS[args.fail_on_vuln]
            flagged = sum(n for s, n in counts.items() if VULN_ORDER.get(s, 9) <= limit)
            if flagged:
                stage.failures.append(
                    f"{flagged} vulnerability(ies) at or above {args.fail_on_vuln.upper()}"
                )
        if args.fail_on_license and denied:
            stage.failures.append(f"{len(denied)} denylisted license(s)")
    return stage


def _save_baseline(args, findings, baseline_doc, revision, git_base) -> bool:
    try:
        save_baseline(
            args.baseline_file,
            updated_baseline(
                args.project_path, findings, baseline_doc, revision, partial=bool(git_base)
            ),
        )
    except OSError as exc:
        print(f"error: could not write baseline: {exc}", file=sys.stderr)
        return False
    return True


def _document(args, revision, git_base, code: CodeStage, deps: DepsStage, failures, failed) -> dict:
    gate_scope = "new" if code.comparison and not args.fail_on_all else "all"
    return {
        "format": "fact-audit-report",
        "version": 1,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": str(Path(args.project_path).resolve()),
        "revision": revision,
        "git_base": git_base,
        "scanners": {"opengrep": code.scanner, "dependencies": deps.scanner},
        "gate": {
            "result": "fail" if failures or failed else "pass",
            "scope": gate_scope,
            "reasons": failures,
        },
        "summary": {
            "total": len(code.findings),
            "by_severity": dict(Counter(f.severity for f in code.findings)),
            "by_status": dict(Counter(code.status.values())),
            "resolved": len(code.comparison.resolved) if code.comparison else 0,
        },
        "findings": [
            {**record(f), "status": code.status.get(f.fingerprint, "")}
            for f in code.findings
        ],
        "resolved": code.comparison.resolved if code.comparison else [],
        "dependencies": deps.summary,
    }


def _print_summary(out: Path, code: CodeStage, deps: DepsStage, failures, failed) -> None:
    print(f"fact-audit: {'FAIL' if failures or failed else 'PASS'}")
    for reason in failures:
        print(f"  - {reason}")
    for detail in code.details:
        print(detail)
    print(f"  code:         {code.line}")
    print(f"  dependencies: {deps.line}; licenses: {deps.license_line}")
    written = [str(path) for path in (out / name for name in ARTIFACTS) if path.exists()]
    print(f"  artifacts:    {', '.join(written) or 'none'}")
