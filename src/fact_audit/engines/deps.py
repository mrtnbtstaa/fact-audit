"""Dependency scan: load the config, discover manifests and collect their dependencies."""

import os
import sys
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path

import yaml

from fact_audit.dataclasses.deps import Config, Dependency, Manifest, ScanResult
from fact_audit.engines.parsers import parse_manifest

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
        manifest = parse_manifest(path, ecosystem, parser)
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
