import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from fact_audit.dataclasses.fidings import Finding
from fact_audit.engines.git_utils import current_revision, get_changed_files
from .engines.deps import DepsError, load_config, scan
from .engines.opengrep import EngineError, run_opengrep
from .findings import (
    EXISTING,
    GATED_STATUSES,
    NEW,
    REINTRODUCED,
    BaselineError,
    baseline_document,
    compare,
    csv_text,
    load_baseline,
    record,
    save_baseline,
    updated_baseline,
)
from .normalize import SEVERITY_ORDER, truncate
from .report import generate_report
from .report_deps import SEVERITY_ORDER as VULN_ORDER, denylisted, render

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


def run_audit(
    project_path: str,
    max_findings: int = 20,
    baseline: str | None = None,
    use_llm: bool = True,
    sarif_path: str | None = None,
) -> tuple[str, list[Finding]]:
    """Return the report and every finding; the report is truncated, the list is not."""
    target_files = None

    if baseline:
        print("Checking Git for changed files...")
        changed_files = get_changed_files(project_path, baseline)

        if not changed_files:
            return "# Code Audit Report\n\nNo changed files found in Git diff. Nothing to audit.\n", []

        print(f"Found {len(changed_files)} changed files.")
        # Opengrep needs absolute paths for the changed files.
        target_files = [str(Path(project_path) / f) for f in changed_files]
    else:
        print("Scanning entire project...")

    findings = run_opengrep(project_path, target_files, sarif_path)
    print(f"Generating report for {min(len(findings), max_findings)} findings...")
    report = generate_report(truncate(findings, max_findings), use_llm)
    return report, findings


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "deps":
        run_deps_command(sys.argv[2:])
        return
    if len(sys.argv) > 1 and sys.argv[1] == "ci":
        run_ci_command(sys.argv[2:])
        return
    if len(sys.argv) > 1 and sys.argv[1] == "baseline":
        run_baseline_command(sys.argv[2:])
        return

    parser = argparse.ArgumentParser(
        description="Fact-based code audit",
        epilog="Run 'fact-audit deps <path>' for dependencies, 'fact-audit ci <path>' for the CI gate, "
        "or 'fact-audit baseline <path>' to record a findings baseline.",
    )
    parser.add_argument("project_path", help="Path to the project to scan")
    parser.add_argument("--out", default="report.md", help="Output file path")
    parser.add_argument("--max-findings", type=int, default=50, help="Max findings to send to LLM")
    parser.add_argument("--diff", action="store_true", help="Only scan files changed in Git")
    parser.add_argument("--baseline", default=None, help="Git ref to diff against (implies --diff)")
    parser.add_argument("--no-llm", action="store_true", help="Skip the LLM and write a deterministic report")
    args = parser.parse_args()

    baseline = args.baseline or ("HEAD" if args.diff else None)
    try:
        report, _ = run_audit(args.project_path, args.max_findings, baseline, not args.no_llm)
    except EngineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(3)

    Path(args.out).write_text(report, encoding="utf-8")
    print(f"Report written to {args.out}")


def run_baseline_command(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="fact-audit baseline", description="Record the current findings as a baseline"
    )
    parser.add_argument("project_path", help="Path to the project to scan")
    parser.add_argument(
        "--out", default=None, help="Baseline file (default: <project>/fact-audit-baseline.json)"
    )
    args = parser.parse_args(argv)

    if not Path(args.project_path).is_dir():
        print(f"error: not a directory: {args.project_path}", file=sys.stderr)
        raise SystemExit(2)

    try:
        _, findings = run_audit(args.project_path, 50, None, False)
    except EngineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(3)

    output = Path(args.out) if args.out else Path(args.project_path) / "fact-audit-baseline.json"
    try:
        save_baseline(output, baseline_document(args.project_path, findings, current_revision(args.project_path)))
    except OSError as exc:
        print(f"error: could not write {output}: {exc}", file=sys.stderr)
        raise SystemExit(2)
    print(f"Baseline written to {output} ({len(findings)} finding(s))")


def run_deps_command(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="fact-audit deps", description="Scan dependency manifests and write a Markdown report"
    )
    parser.add_argument("project_path", help="Path to the project to scan")
    parser.add_argument("--out", default=None, help="Output file (default: deps-report.md)")
    parser.add_argument("--online", action="store_true", help="Look up advisories, latest versions and licenses")
    parser.add_argument("--config", default=None, help="Config file (default: <project>/.depscan.yml)")
    parser.add_argument("--allow-empty", action="store_true", help="Exit 0 when no manifests are found")
    args = parser.parse_args(argv)

    try:
        config = load_config(Path(args.project_path), args.config)
        config.online = config.online or args.online
        config.allow_empty = config.allow_empty or args.allow_empty
        if args.out:
            config.output = args.out
        result = scan(args.project_path, config)
        if config.online:
            from .engines.feeds import enrich

            enrich(result)
        output = Path(config.output)
        _write_report(output, render(result))
    except DepsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)

    print(output)
    if not result.manifests and not config.allow_empty:
        raise SystemExit(1)


def run_ci_command(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="fact-audit ci", description="Run the code audit and dependency scan as a CI gate"
    )
    parser.add_argument("project_path", help="Path to the project to audit")
    parser.add_argument("--diff", action="store_true", help="Only audit files changed in Git")
    parser.add_argument("--baseline", default=None, help="Git ref to diff against (implies --diff)")
    parser.add_argument(
        "--baseline-file", default=None, help="Findings baseline to compare against (see 'fact-audit baseline')"
    )
    parser.add_argument("--update-baseline", action="store_true", help="Rewrite the baseline file after a successful run")
    parser.add_argument("--online", action="store_true", help="Check advisories, latest versions and licenses")
    parser.add_argument(
        "--out-dir", default=".", help="Directory for the Markdown, SARIF, JSON and CSV reports"
    )
    parser.add_argument("--no-llm", action="store_true", help="Skip the LLM and write a deterministic report")
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
        "--max-new", type=int, default=None, help="Fail when more than this many new findings appear (needs --baseline-file)"
    )
    parser.add_argument(
        "--fail-on-vuln", choices=["critical", "high", "medium", "low", "none"], default="high",
        help="Fail on advisories at or above this severity (requires --online)",
    )
    parser.add_argument("--fail-on-license", action="store_true", help="Fail on denylisted licenses")
    args = parser.parse_args(argv)

    if not Path(args.project_path).is_dir():
        print(f"error: not a directory: {args.project_path}", file=sys.stderr)
        raise SystemExit(2)
    if (args.max_new is not None or args.update_baseline) and not args.baseline_file:
        print("error: --max-new and --update-baseline require --baseline-file", file=sys.stderr)
        raise SystemExit(2)

    baseline_doc = None
    if args.baseline_file:
        try:
            baseline_doc = load_baseline(args.baseline_file, args.project_path)
        except BaselineError as exc:
            print(f"error: {exc}", file=sys.stderr)
            raise SystemExit(2)

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    details: list[str] = []
    stage_failed = False
    code_status = "failed"
    deps_status = "not run"
    code_line = "failed"
    vuln_line = "not checked (offline)"
    license_line = "not checked (offline)"
    dependencies = {"online": False, "vulnerabilities": {}, "denylisted_licenses": 0}
    comparison = None
    status: dict[str, str] = {}
    findings: list[Finding] = []
    revision = current_revision(args.project_path)
    git_base = args.baseline or ("HEAD" if args.diff else None)

    try:
        report, findings = run_audit(
            args.project_path, 50, git_base, not args.no_llm, str(out / "fact-audit.sarif")
        )
        code_status = "ok"
        comparison = compare(findings, baseline_doc) if baseline_doc else None
        if comparison and git_base:
            comparison.resolved = []  # diff-scoped scan: absence proves nothing
        if comparison:
            status = comparison.status
            counts = Counter(status.values())
            report += (
                "\n## Baseline comparison\n\n"
                f"- new: {counts[NEW]}, reintroduced: {counts[REINTRODUCED]}, "
                f"existing: {counts[EXISTING]}, resolved: {len(comparison.resolved)}\n"
            )
        (out / "report.md").write_text(report, encoding="utf-8")
        code_line = f"{len(findings)} finding(s)"
        if comparison:
            code_line += f" ({sum(1 for s in status.values() if s in GATED_STATUSES)} new)"

        if args.fail_on != "none":
            limit = FAIL_ON_LIMITS[args.fail_on]
            gated = (
                findings
                if args.fail_on_all or not comparison
                else [f for f in findings if status[f.fingerprint] in GATED_STATUSES]
            )
            flagged = [f for f in gated if SEVERITY_ORDER.get(f.severity, 99) <= limit]
            if flagged:
                scope = "new/reintroduced" if comparison and not args.fail_on_all else "all"
                failures.append(
                    f"{len(flagged)} {scope} code finding(s) at or above {args.fail_on.upper()}"
                )
                details += [f"    {f.file}:{f.line} {f.rule_id}" for f in flagged[:5]]

        if args.max_new is not None:
            new_count = sum(1 for s in status.values() if s in GATED_STATUSES)
            if new_count > args.max_new:
                failures.append(f"{new_count} new/reintroduced finding(s) exceed --max-new {args.max_new}")
    except Exception as exc:
        print(f"error: code audit failed: {exc}", file=sys.stderr)
        stage_failed = True

    try:
        config = load_config(Path(args.project_path), None)
        config.online = config.online or args.online
        result = scan(args.project_path, config)
        if config.online:
            from .engines.feeds import enrich

            enrich(result)
        _write_report(out / "deps-report.md", render(result))
        deps_status = "ok"

        deps = [d for m in result.manifests if not m.error for d in m.dependencies]
        counts = Counter(a.severity for d in deps for a in d.advisories)
        denied = [d for d in deps if denylisted(d.license, config.denylist)]
        dependencies = {
            "online": bool(config.online),
            "vulnerabilities": dict(counts),
            "denylisted_licenses": len(denied),
        }
        if config.online:
            vuln_line = (
                ", ".join(
                    f"{counts[s]} {s.lower()}"
                    for s in sorted(counts, key=lambda s: VULN_ORDER.get(s, 9))
                )
                or "no advisories"
            )
            license_line = f"{len(denied)} denylisted"
            if args.fail_on_vuln != "none":
                limit = {"critical": 0, "high": 1, "medium": 2, "low": 3}[args.fail_on_vuln]
                flagged = sum(
                    n for s, n in counts.items() if VULN_ORDER.get(s, 9) <= limit
                )
                if flagged:
                    failures.append(
                        f"{flagged} vulnerability(ies) at or above {args.fail_on_vuln.upper()}"
                    )
            if args.fail_on_license and denied:
                failures.append(f"{len(denied)} denylisted license(s)")
    except DepsError as exc:
        print(f"error: dependency scan failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
    except Exception as exc:
        print(f"error: dependency scan failed: {exc}", file=sys.stderr)
        stage_failed = True

    if args.update_baseline and not stage_failed:
        try:
            save_baseline(
                args.baseline_file,
                updated_baseline(args.project_path, findings, baseline_doc, revision, partial=bool(git_base)),
            )
        except OSError as exc:
            print(f"error: could not write baseline: {exc}", file=sys.stderr)
            stage_failed = True

    gate_scope = "new" if comparison and not args.fail_on_all else "all"
    document = {
        "format": "fact-audit-report",
        "version": 1,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": str(Path(args.project_path).resolve()),
        "revision": revision,
        "git_base": git_base,
        "scanners": {"opengrep": code_status, "dependencies": deps_status},
        "gate": {
            "result": "fail" if failures or stage_failed else "pass",
            "scope": gate_scope,
            "reasons": failures,
        },
        "summary": {
            "total": len(findings),
            "by_severity": dict(Counter(f.severity for f in findings)),
            "by_status": dict(Counter(status.values())),
            "resolved": len(comparison.resolved) if comparison else 0,
        },
        "findings": [{**record(f), "status": status.get(f.fingerprint, "")} for f in findings],
        "resolved": comparison.resolved if comparison else [],
        "dependencies": dependencies,
    }
    (out / "fact-audit.json").write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    (out / "fact-audit.csv").write_text(csv_text(findings, status), encoding="utf-8")

    print(f"fact-audit: {'FAIL' if failures or stage_failed else 'PASS'}")
    for reason in failures:
        print(f"  - {reason}")
    for detail in details:
        print(detail)
    print(f"  code:         {code_line}")
    print(f"  dependencies: {vuln_line}; licenses: {license_line}")
    written = [
        p
        for p in (
            out / "report.md",
            out / "deps-report.md",
            out / "fact-audit.sarif",
            out / "fact-audit.json",
            out / "fact-audit.csv",
        )
        if p.exists()
    ]
    print(f"  artifacts:    {', '.join(str(p) for p in written) or 'none'}")

    if stage_failed:
        raise SystemExit(3)
    raise SystemExit(1 if failures else 0)


def _write_report(path: Path, text: str) -> None:
    # FR-010: never clobber a file this scanner did not produce.
    if path.exists():
        try:
            with path.open(encoding="utf-8") as handle:
                head = handle.read(64)
        except (OSError, UnicodeDecodeError):
            head = ""
        if not head.startswith("# Dependency Scan Report"):
            raise DepsError(f"refusing to overwrite {path}: not a dependency scan report")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
