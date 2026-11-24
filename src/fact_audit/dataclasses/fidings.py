from dataclasses import dataclass, field

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
