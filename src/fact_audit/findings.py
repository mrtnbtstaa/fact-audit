"""The Finding model plus its normalization, fingerprinting and CSV export."""

import csv
import hashlib
import io
from dataclasses import dataclass, field
from pathlib import Path

FINGERPRINT_VERSION = 1

# Opengrep/semgrep levels. Anything else stays UNKNOWN rather than being guessed.
SCANNER_SEVERITIES = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}

# Normalized scale. The legacy scanner keys are aliases so existing reports and
# `--fail-on error|warning|info` keep their meaning.
SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "ERROR": 1,
    "MEDIUM": 2,
    "WARNING": 2,
    "LOW": 3,
    "INFO": 4,
    "UNKNOWN": 5,
}


@dataclass
class Finding:
    source: str
    file: str
    line: int
    severity: str
    message: str
    rule_id: str
    scanner_severity: str = ""
    confidence: str = "UNKNOWN"
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    fingerprint: str = ""


def normalize(project_path: str, findings: list[Finding]) -> list[Finding]:
    """Fill the normalized fields in place; keep the scanner's original severity."""
    root = Path(project_path).resolve()
    for finding in findings:
        path = Path(finding.file)
        try:
            finding.file = (path if path.is_absolute() else root / path).resolve().relative_to(root).as_posix()
        except (ValueError, OSError):
            pass  # outside the project: keep what the scanner reported
        finding.scanner_severity = finding.severity
        finding.severity = SCANNER_SEVERITIES.get(finding.severity.upper(), "UNKNOWN")
        finding.fingerprint = fingerprint(finding)
    return findings


def fingerprint(finding: Finding) -> str:
    # Deliberately no line number: moving code must not create a new finding.
    # shortcut: identical findings in one file share a fingerprint; add an
    # occurrence index if that ever matters.
    key = "\0".join(
        (
            str(FINGERPRINT_VERSION),
            finding.file,
            finding.rule_id,
            " ".join(finding.message.split()),
        )
    )
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def record(finding: Finding) -> dict:
    return {
        "fingerprint": finding.fingerprint,
        "rule_id": finding.rule_id,
        "file": finding.file,
        "line": finding.line,
        "severity": finding.severity,
        "scanner_severity": finding.scanner_severity,
        "confidence": finding.confidence,
        "cwe": finding.cwe,
        "owasp": finding.owasp,
        "message": finding.message,
    }


def truncate(findings: list[Finding], max_findings: int = 30) -> list[Finding]:
    ordered = sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.file, f.line))
    return ordered[:max_findings]


def _csv_cell(value) -> str:
    text = str(value)
    # Spreadsheets evaluate cells starting with these characters as formulas.
    return "'" + text if text.startswith(("=", "+", "-", "@", "\t", "\r")) else text


def csv_text(findings: list[Finding], status: dict[str, str]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        (
            "fingerprint", "status", "severity", "confidence", "rule_id",
            "cwe", "owasp", "file", "line", "message",
        )
    )
    for finding in findings:
        writer.writerow(
            [
                _csv_cell(value)
                for value in (
                    finding.fingerprint,
                    status.get(finding.fingerprint, ""),
                    finding.severity,
                    finding.confidence,
                    finding.rule_id,
                    "; ".join(finding.cwe),
                    "; ".join(finding.owasp),
                    finding.file,
                    finding.line,
                    finding.message,
                )
            ]
        )
    return buffer.getvalue()
