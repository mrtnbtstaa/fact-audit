import json
import os
import re
import sys
import tomllib
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path

import yaml

from fact_audit.dataclasses.deps import Config, Dependency, Manifest, ScanResult

CONFIG_NAME = ".depscan.yml"
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    ".depscan-cache",
    "dist",
    "build",
    "target",
}
VENDOR_DIRS = {"vendor", "third_party"}
# filename -> (ecosystem, parser)
MANIFESTS = {
    "package.json": ("npm", "package_json"),
    "package-lock.json": ("npm", "npm_lock"),
    "requirements.txt": ("python", "requirements"),
    "pyproject.toml": ("python", "pyproject"),
    "go.mod": ("go", "go_mod"),
    "go.sum": ("go", "go_sum"),
}
EXTRA_PARSER = {"npm": "package_json", "python": "requirements", "go": "go_mod"}
PINNED_NPM = re.compile(r"^v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?)$")
REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")


class DepsError(Exception):
    """A user-facing error: bad path, bad config, unsafe output."""


def load_config(target: Path, explicit: str | None = None) -> Config:
    path = Path(explicit) if explicit else target / CONFIG_NAME
    config = Config()
    if not path.is_file():
        if explicit:
            raise DepsError(f"config file not found: {path}")
        return config

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8-sig")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise DepsError(f"cannot read config {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise DepsError(f"config {path} must be a mapping")

    denylist = data.get("denylist")
    if denylist is not None:
        if not isinstance(denylist, list) or not all(isinstance(x, str) for x in denylist):
            raise DepsError(f"config {path}: denylist must be a list of strings")
        config.denylist = denylist  # a custom list fully overrides the default

    extra = data.get("extra_manifests")
    if extra is not None:
        if not isinstance(extra, dict) or any(
            eco not in EXTRA_PARSER for eco in extra.values()
        ):
            raise DepsError(
                f"config {path}: extra_manifests must map glob -> one of {sorted(EXTRA_PARSER)}"
            )
        config.extra_manifests = dict(extra)

    for key in ("output", "cache_ttl_hours"):
        if key in data and not isinstance(data[key], (str, int)):
            raise DepsError(f"config {path}: {key} has the wrong type")
    if "output" in data:
        output = Path(str(data["output"]))
        root = target.resolve()
        resolved = (target / output).resolve()
        # A scanned repository must not choose a write path outside itself.
        if output.is_absolute() or resolved == root or not resolved.is_relative_to(root):
            raise DepsError(f"config {path}: output must be a file inside the project")
        config.output = str(target / output)
    if "cache_ttl_hours" in data:
        config.cache_ttl_hours = int(data["cache_ttl_hours"])
    if "allow_empty" in data:
        config.allow_empty = bool(data["allow_empty"])
    if "online" in data:
        config.online = bool(data["online"])
    return config


def scan(target: str, config: Config) -> ScanResult:
    root = Path(target)
    if not root.is_dir():
        raise DepsError(f"not a directory: {target}")
    root = root.resolve()

    result = ScanResult(
        target=str(root),
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        config=config,
    )
    found, result.vendored = _discover(root, config.extra_manifests)
    for path, ecosystem, parser in found:
        manifest = _parse(path, ecosystem, parser)
        result.manifests.append(manifest)
        rel = _relative(path, root)
        if manifest.error:
            print(f"failed: {rel}: {manifest.error}", file=sys.stderr)
        else:
            print(f"scanned: {rel} ({len(manifest.dependencies)} dependencies)", file=sys.stderr)

    _apply_locks(result.manifests)
    return result


def _discover(root: Path, extra: dict[str, str]) -> tuple[list[tuple[Path, str, str]], list[str]]:
    found: list[tuple[Path, str, str]] = []
    vendored: list[str] = []
    for current, dirs, files in os.walk(root, onerror=_walk_error):
        dirs.sort()
        for name in dirs:
            if name in VENDOR_DIRS:
                vendored.append(_relative(Path(current, name), root))
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and d not in VENDOR_DIRS]
        for name in sorted(files):
            if name in MANIFESTS:
                ecosystem, parser = MANIFESTS[name]
            else:
                ecosystem = next(
                    (eco for glob, eco in extra.items() if fnmatch(name, glob)), None
                )
                if ecosystem is None:
                    continue
                parser = EXTRA_PARSER[ecosystem]
            found.append((Path(current, name), ecosystem, parser))
    return found, vendored


def _walk_error(exc: OSError) -> None:
    print(f"skipped: {exc}", file=sys.stderr)


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path)


def _parse(path: Path, ecosystem: str, parser: str) -> Manifest:
    manifest = Manifest(path=str(path), kind=path.name, ecosystem=ecosystem)
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        manifest.error = str(exc)
        return manifest

    try:
        if parser == "package_json":
            manifest.dependencies = _package_json(text)
        elif parser == "npm_lock":
            manifest.dependencies = _npm_lock(text)
        elif parser == "pyproject":
            manifest.dependencies = _pyproject(text)
        elif parser == "go_mod":
            manifest.dependencies = _go_mod(text)
        elif parser == "go_sum":
            manifest.dependencies = _go_sum(text)
        else:
            manifest.dependencies = _requirements(text)
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, ValueError) as exc:
        manifest.error = _error_text(exc)
        manifest.dependencies = []
    return manifest


def _error_text(exc: Exception) -> str:
    if isinstance(exc, json.JSONDecodeError):
        return f"{exc.msg} (line {exc.lineno}, column {exc.colno})"
    return str(exc)


def _package_json(text: str) -> list[Dependency]:
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("package.json must contain an object")
    deps = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        entries = data.get(section) or {}
        if not isinstance(entries, dict):
            raise ValueError(f"{section} must be an object")
        for name, spec in entries.items():
            if not isinstance(spec, str):
                continue
            pinned = PINNED_NPM.match(spec.strip())
            deps.append(
                Dependency(
                    name=name,
                    ecosystem="npm",
                    declared=spec,
                    version=pinned.group(1) if pinned else None,
                    is_range=pinned is None,
                )
            )
    return deps


def _npm_lock(text: str) -> list[Dependency]:
    data = json.loads(text)
    deps: list[Dependency] = []
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfile v2/v3
        for key, entry in packages.items():
            if not key or not isinstance(entry, dict) or entry.get("link"):
                continue
            version = entry.get("version")
            if not version:
                continue
            deps.append(
                Dependency(
                    name=key.split("node_modules/")[-1],
                    ecosystem="npm",
                    declared=version,
                    version=version,
                    license=entry.get("license") or "UNKNOWN",
                    transitive=True,
                )
            )
        return deps

    def walk(node: dict) -> None:  # lockfile v1
        for name, entry in (node or {}).items():
            if not isinstance(entry, dict):
                continue
            if entry.get("version"):
                deps.append(
                    Dependency(
                        name=name,
                        ecosystem="npm",
                        declared=entry["version"],
                        version=entry["version"],
                        transitive=True,
                    )
                )
            walk(entry.get("dependencies"))

    walk(data.get("dependencies") or {})
    return deps


def _requirements(text: str) -> list[Dependency]:
    deps = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = REQUIREMENT.match(line)
        if not match:
            continue
        name, spec = match.group(1), match.group(2).strip()
        version = None
        if spec.startswith("==="):
            version = spec[3:].strip()
        elif spec.startswith("=="):
            version = spec[2:].strip()
        if version and "*" in version:
            version = None
        deps.append(
            Dependency(
                name=name,
                ecosystem="python",
                declared=spec or "*",
                version=version,
                is_range=version is None,
            )
        )
    return deps


def _pyproject(text: str) -> list[Dependency]:
    data = tomllib.loads(text)
    project = data.get("project") or {}
    requirements = list(project.get("dependencies") or [])
    for group in (project.get("optional-dependencies") or {}).values():
        requirements.extend(group)
    return _requirements("\n".join(requirements))


def _go_mod(text: str) -> list[Dependency]:
    deps = []
    in_require = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if line.startswith("require "):
            line = line[len("require "):].strip()
        elif not in_require:
            continue
        parts = line.split()
        if len(parts) < 2 or not parts[1].startswith("v"):
            continue
        deps.append(
            Dependency(
                name=parts[0],
                ecosystem="go",
                declared=parts[1],
                version=parts[1][1:],
            )
        )
    return deps


def _go_sum(text: str) -> list[Dependency]:
    seen: set[tuple[str, str]] = set()
    deps = []
    for raw in text.splitlines():
        parts = raw.split()
        if len(parts) < 2:
            continue
        name = parts[0]
        version = parts[1].removesuffix("/go.mod").lstrip("v")
        if not version or (name, version) in seen:
            continue
        seen.add((name, version))
        deps.append(
            Dependency(
                name=name,
                ecosystem="go",
                declared=f"v{version}",
                version=version,
                transitive=True,
            )
        )
    return deps


def _apply_locks(manifests: list[Manifest]) -> None:
    """Fill resolved versions and licenses from a lockfile next to package.json."""
    locks = {
        str(Path(m.path).parent): m
        for m in manifests
        if Path(m.path).name == "package-lock.json"
    }
    for manifest in manifests:
        if Path(manifest.path).name != "package.json":
            continue
        lock = locks.get(str(Path(manifest.path).parent))
        if lock is None:
            continue
        resolved: dict[str, Dependency] = {}
        for dep in lock.dependencies:
            resolved.setdefault(dep.name, dep)
        for dep in manifest.dependencies:
            source = resolved.get(dep.name)
            if source is None:
                continue
            if dep.version is None and source.version:
                dep.version = source.version
            if dep.license == "UNKNOWN" and source.license != "UNKNOWN":
                dep.license = source.license
