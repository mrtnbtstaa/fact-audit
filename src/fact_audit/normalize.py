from fact_audit.dataclasses.fidings import Finding


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

def truncate(findings: list[Finding], max_findings: int = 30) -> list[Finding]:
    sorted_f = sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.file, f.line))
    return sorted_f[:max_findings]
