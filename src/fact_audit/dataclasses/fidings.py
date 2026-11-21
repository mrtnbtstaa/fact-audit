from dataclasses import dataclass

@dataclass
class Finding:
    source: str
    file: str
    line: int
    severity: str
    message: str
    rule_id: str