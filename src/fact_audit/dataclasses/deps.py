from dataclasses import dataclass, field

DEFAULT_DENYLIST = [
    "AGPL-3.0",
    "GPL-3.0",
    "GPL-2.0",
    "CC-BY-NC-*",
    "SSPL",
    "BUSL-*",
    "Elastic-2.0",
]


@dataclass
class Advisory:
    id: str
    severity: str
    summary: str
    url: str
    sources: list[str] = field(default_factory=list)


@dataclass
class Dependency:
    name: str
    ecosystem: str
    declared: str
    version: str | None = None
    is_range: bool = False
    latest: str | None = None
    behind: str = "unknown"
    license: str = "UNKNOWN"
    advisories: list[Advisory] = field(default_factory=list)
    transitive: bool = False


@dataclass
class Manifest:
    path: str
    kind: str
    ecosystem: str
    dependencies: list[Dependency] = field(default_factory=list)
    error: str | None = None


@dataclass
class Config:
    denylist: list[str] = field(default_factory=lambda: list(DEFAULT_DENYLIST))
    extra_manifests: dict[str, str] = field(default_factory=dict)
    output: str = "deps-report.md"
    allow_empty: bool = False
    online: bool = False
    cache_ttl_hours: int = 24


@dataclass
class ScanResult:
    target: str
    timestamp: str
    config: Config
    manifests: list[Manifest] = field(default_factory=list)
    vendored: list[str] = field(default_factory=list)
