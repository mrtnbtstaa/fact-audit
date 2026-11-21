import hashlib
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from fact_audit.dataclasses.deps import Advisory, Dependency, ScanResult

OSV_QUERY = "https://api.osv.dev/v1/query"
DEPS_DEV = "https://api.deps.dev/v3alpha/systems/{system}/packages/{name}/versions/{version}"
OSV_ECOSYSTEM = {"npm": "npm", "python": "PyPI", "go": "Go"}
DEPS_DEV_SYSTEM = {"npm": "npm", "python": "pypi", "go": "go"}
SEVERITIES = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}
CACHE_DIR = Path.home() / ".depscan-cache"
VERSION_NUMBERS = re.compile(r"(\d+)\.(\d+)\.(\d+)")
LOCAL_SPECS = ("file:", "git+", "git:", "workspace:", "link:", "portal:", "npm:", "http:", "https:", "@")


class Feeds:
    def __init__(self, cache_dir: Path = CACHE_DIR, ttl_hours: int = 24):
        self.cache_dir = cache_dir
        self.ttl_seconds = ttl_hours * 3600

    def latest(self, dep: Dependency) -> str | None:
        if dep.ecosystem == "npm":
            data = self._json(f"https://registry.npmjs.org/{_quote(dep.name)}/latest")
            return data.get("version")
        if dep.ecosystem == "python":
            return (self._json(_pypi_url(dep.name)).get("info") or {}).get("version")
        if dep.ecosystem == "go":
            version = self._json(
                f"https://proxy.golang.org/{_quote(dep.name)}/@latest"
            ).get("Version")
            return version[1:] if version and version.startswith("v") else version
        return None

    def resolve_python(self, name: str, spec: str) -> tuple[str | None, str | None]:
        """Highest published version satisfying a PEP 440 range, plus the latest."""
        try:
            wanted = SpecifierSet(spec)
        except InvalidSpecifier:
            return None, None
        data = self._json(_pypi_url(name))
        latest = (data.get("info") or {}).get("version")
        candidates = []
        for raw in (data.get("releases") or {}):
            try:
                version = Version(raw)
            except InvalidVersion:
                continue
            if version.is_prerelease:
                continue
            if wanted.contains(version):
                candidates.append(version)
        return (str(max(candidates)) if candidates else None), latest

    def license(self, dep: Dependency) -> str | None:
        system = DEPS_DEV_SYSTEM[dep.ecosystem]
        version = dep.version or ""
        if dep.ecosystem == "go" and not version.startswith("v"):
            version = f"v{version}"
        data = self._json(
            DEPS_DEV.format(
                system=system, name=_quote(dep.name), version=_quote(version)
            )
        )
        licenses = data.get("licenses") or []
        return licenses[0] if licenses else None

    def advisories(self, dep: Dependency) -> list[Advisory]:
        body = {
            "package": {"name": dep.name, "ecosystem": OSV_ECOSYSTEM[dep.ecosystem]},
            "version": dep.version,
        }
        data = self._json(OSV_QUERY, body)
        found: dict[str, Advisory] = {}
        aliases: dict[str, str] = {}
        for vuln in data.get("vulns") or []:
            advisory_id = vuln.get("id")
            if not advisory_id:
                continue
            # OSV lists the same issue under several IDs (GHSA, GO, CVE); collapse them.
            keys = [advisory_id, *(vuln.get("aliases") or [])]
            known = next((aliases[key] for key in keys if key in aliases), None)
            if known:
                existing = found[known]
                if existing.severity == "UNKNOWN" and _severity(vuln) != "UNKNOWN":
                    existing.severity = _severity(vuln)
                for key in keys:
                    aliases.setdefault(key, known)
                continue
            found[advisory_id] = Advisory(
                id=advisory_id,
                severity=_severity(vuln),
                summary=_summary(vuln),
                url=_advisory_url(vuln),
                sources=["OSV"],
            )
            for key in keys:
                aliases[key] = advisory_id
        return list(found.values())

    def _json(self, url: str, body: dict | None = None) -> dict:
        key = hashlib.sha256(
            (url + json.dumps(body, sort_keys=True)).encode("utf-8")
        ).hexdigest()
        cached = self.cache_dir / f"{key}.json"
        if cached.is_file() and time.time() - cached.stat().st_mtime < self.ttl_seconds:
            try:
                return json.loads(cached.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                pass  # stale or corrupt cache entry: refetch
        request = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8") if body else None,
            headers={"Content-Type": "application/json", "User-Agent": "fact-audit-deps"},
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        cached.write_text(json.dumps(data), encoding="utf-8")
        return data


def enrich(result: ScanResult) -> None:
    feeds = Feeds(ttl_hours=result.config.cache_ttl_hours)
    for manifest in result.manifests:
        if manifest.error:
            continue
        for dep in manifest.dependencies:
            if not _lookup_allowed(dep):
                continue
            if dep.ecosystem == "python" and dep.version is None:
                # shortcut: only PEP 440 ranges are resolved; npm ranges without a
                # lockfile stay unknown, add a semver resolver when that matters.
                resolved = _safe(feeds.resolve_python, dep.name, dep.declared)
                if resolved:
                    dep.version, dep.latest = resolved
            dep.latest = dep.latest or _safe(feeds.latest, dep)
            if dep.version and dep.license == "UNKNOWN":
                dep.license = _safe(feeds.license, dep) or dep.license
            if dep.version:
                dep.advisories = _safe(feeds.advisories, dep) or []
            dep.behind = behind(dep.version, dep.latest)
        print(f"looked up: {manifest.path}", file=sys.stderr)


def _safe(call, *args):
    try:
        return call(*args)
    except Exception as exc:  # a dead feed must not abort the scan
        print(f"lookup failed: {exc}", file=sys.stderr)
        return None


def behind(installed: str | None, latest: str | None) -> str:
    current, newest = _numbers(installed), _numbers(latest)
    if not current or not newest:
        return "unknown"
    if current == newest:
        return "current"
    if current[0] != newest[0]:
        return "major"
    if current[1] != newest[1]:
        return "minor"
    return "patch"


def _numbers(version: str | None) -> tuple[int, int, int] | None:
    match = VERSION_NUMBERS.match(version or "")
    return tuple(int(part) for part in match.groups()) if match else None


def _lookup_allowed(dep: Dependency) -> bool:
    declared = (dep.declared or "").lower()
    return not any(declared.startswith(spec) for spec in LOCAL_SPECS)


def _quote(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def _pypi_url(name: str) -> str:
    return f"https://pypi.org/pypi/{_quote(name)}/json"


def _severity(vuln: dict) -> str:
    for key in ("database_specific", "ecosystem_specific"):
        raw = (vuln.get(key) or {}).get("severity")
        if isinstance(raw, str) and raw.upper() in SEVERITIES:
            return SEVERITIES[raw.upper()]
    return "UNKNOWN"


def _summary(vuln: dict) -> str:
    text = vuln.get("summary") or (vuln.get("details") or "").strip()
    return " ".join(text.split())[:200]


def _advisory_url(vuln: dict) -> str:
    for reference in vuln.get("references") or []:
        if reference.get("type") == "ADVISORY" and reference.get("url"):
            return reference["url"]
    return f"https://osv.dev/vulnerability/{vuln.get('id', '')}"
