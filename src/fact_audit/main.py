import argparse
import sys
from pathlib import Path

from fact_audit.engines.git_utils import get_changed_files
from .engines.deps import DepsError, load_config, scan
from .engines.semgrep import run_semgrep
from .normalize import truncate
from .report import generate_report
from .report_deps import render

def run_audit(project_path: str, max_findings: int = 20, use_diff: bool = False) -> str:
    target_files = None
    
    if use_diff:
        print("Checking Git for changed files...")
        changed_files = get_changed_files(project_path)
        
        if not changed_files:
            return "# Code Audit Report\n\nNo changed files found in Git diff. Nothing to audit."
            
        print(f"Found {len(changed_files)} changed files.")
        # Convert relative git paths to absolute paths so Semgrep can find them
        target_files = [str(Path(project_path) / f) for f in changed_files]
    else:
        print("Scanning entire project...")

    # Pass target_files to run_semgrep
    findings = run_semgrep(project_path, target_files)
    findings = truncate(findings, max_findings)
    
    print(f"Generating report for {len(findings)} findings...")
    report = generate_report(findings)
    return report

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "deps":
        run_deps_command(sys.argv[2:])
        return

    parser = argparse.ArgumentParser(
        description="Fact-based code audit",
        epilog="Run 'fact-audit deps <path>' to scan dependency manifests instead.",
    )
    parser.add_argument("project_path", help="Path to the project to scan")
    parser.add_argument("--out", default="report.md", help="Output file path")
    parser.add_argument("--max-findings", type=int, default=50, help="Max findings to send to LLM")
    
    # Add the --diff flag here
    parser.add_argument("--diff", action="store_true", help="Only scan files changed in Git")
    
    args = parser.parse_args()

    # Pass the --diff flag into the core function
    report = run_audit(args.project_path, args.max_findings, args.diff)
    
    Path(args.out).write_text(report, encoding="utf-8")
    print(f"Report written to {args.out}")


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