"""Command line entry point: dispatch to the audit, dependency, CI and baseline commands."""

import argparse
import sys
from pathlib import Path

from .audit import run_audit
from .baseline import baseline_document, save_baseline
from .ci import run_ci_command
from .engines.deps import DepsError, load_config, scan
from .engines.feeds import enrich
from .engines.git_utils import current_revision
from .engines.opengrep import EngineError
from .report_deps import write_report


def main() -> None:
    command = sys.argv[1] if len(sys.argv) > 1 else None
    if command == "deps":
        run_deps_command(sys.argv[2:])
    elif command == "ci":
        run_ci_command(sys.argv[2:])
    elif command == "baseline":
        run_baseline_command(sys.argv[2:])
    else:
        run_audit_command(sys.argv[1:])


def run_audit_command(argv: list[str]) -> None:
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
    args = parser.parse_args(argv)

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
            enrich(result)
        output = write_report(Path(config.output), result)
    except DepsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)

    print(output)
    if not result.manifests and not config.allow_empty:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
