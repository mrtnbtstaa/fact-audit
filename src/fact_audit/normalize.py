from fact_audit.dataclasses.fidings import Finding


SEVERITY_ORDER = {"ERROR": 0, "WARNING": 1, "INFO": 2}

def truncate(findings: list[Finding], max_findings: int = 30) -> list[Finding]:
    sorted_f = sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.file, f.line))
    return sorted_f[:max_findings]