"""Run the code audit: pick the files, run Opengrep and generate the report."""

from pathlib import Path

from fact_audit.engines.git_utils import get_changed_files
from fact_audit.engines.opengrep import run_opengrep
from fact_audit.findings import Finding, truncate
from fact_audit.report import generate_report


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
