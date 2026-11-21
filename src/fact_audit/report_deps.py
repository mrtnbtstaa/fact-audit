"""Render a ScanResult as deterministic Markdown."""

from collections import Counter
from fnmatch import fnmatch
from pathlib import Path

from fact_audit.dataclasses.deps import Config, Dependency, Manifest, ScanResult
from fact_audit.engines.deps import MANIFESTS

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def render(result: ScanResult) -> str:
    config = result.config
    lines = [
        "# Dependency Scan Report",
        "",
        f"Generated: {result.timestamp}  ",
        f"Target: `{result.target}`  ",
        f"Mode: {'online' if config.online else 'offline'}",
        "",
    ]
    lines += _summary(result)
    lines += _manifests(result)
    lines += _dependencies(result)
    lines += _vulnerabilities(result)
    lines += _licenses(result)
    lines += _configuration(config)
    return "\n".join(lines).rstrip() + "\n"


def _summary(result: ScanResult) -> list[str]:
    parsed = [m for m in result.manifests if not m.error]
    failed = [m for m in result.manifests if m.error]
    deps = [d for m in parsed for d in m.dependencies]
    advisories = [a for d in deps for a in d.advisories]
    counts = Counter(a.severity for a in advisories)
    lines = [
        "## Executive Summary",
        "",
        f"- Manifests found: {len(result.manifests)} "
        f"(parsed {len(parsed)}, failed {len(failed)})",
        f"- Total dependency declarations: {len(deps)}",
        f"- Unique dependencies: {len({(d.ecosystem, d.name) for d in deps})}",
        f"- Dependencies with at least one matched advisory: "
        f"{sum(1 for d in deps if d.advisories)}",
        f"- Advisories: {counts['CRITICAL']} Critical, {counts['HIGH']} High, "
        f"{counts['MEDIUM']} Medium, {counts['LOW']} Low",
        f"- Dependencies with unknown license: {sum(1 for d in deps if d.license == 'UNKNOWN')}",
        f"- Dependencies at least one major version behind: "
        f"{sum(1 for d in deps if d.behind == 'major')}",
        "",
    ]
    if not result.config.online:
        lines += [
            "> Run was **offline**: vulnerability, latest-version and license "
            "lookups were not performed, so `unknown` means *not checked*, not *no findings*.",
            "",
        ]
    if result.vendored:
        lines += [
            f"> Vendored code detected ({', '.join(f'`{v}`' for v in result.vendored)}); "
            "vendored dependencies are not enumerated.",
            "",
        ]
    return lines


def _manifests(result: ScanResult) -> list[str]:
    lines = ["## Manifests", ""]
    if not result.manifests:
        looked_for = ", ".join(f"`{name}`" for name in sorted(MANIFESTS))
        lines += [
            f"No supported dependency manifests were found in `{result.target}`.",
            "",
            f"Looked for: {looked_for}, plus any configured `extra_manifests`.",
            "",
        ]
        return lines

    for manifest in result.manifests:
        if manifest.error:
            continue
        lines += [
            f"### `{_rel(manifest, result)}`",
            "",
            f"- Ecosystem: {manifest.ecosystem}",
            f"- Dependencies: {len(manifest.dependencies)}",
            "",
        ]

    lines += ["### Parse failures", ""]
    failed = [m for m in result.manifests if m.error]
    if failed:
        for manifest in failed:
            lines.append(f"- **`{_rel(manifest, result)}`** — {_cell(manifest.error)}")
    else:
        lines.append("No parse failures.")
    lines.append("")
    return lines


def _dependencies(result: ScanResult) -> list[str]:
    lines = ["## Dependencies", ""]
    if not result.manifests:
        lines += ["No dependencies to report.", ""]
        return lines
    for manifest in result.manifests:
        if manifest.error:
            continue
        if not manifest.dependencies:
            lines += [f"### `{_rel(manifest, result)}`", "", "No dependencies.", ""]
            continue
        lines += [
            f"### `{_rel(manifest, result)}`",
            "",
            "| Package | Installed | Ecosystem | Latest | Behind | License |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for dep in sorted(manifest.dependencies, key=lambda d: d.name.lower()):
            behind = f"**{dep.behind}**" if dep.behind == "major" else dep.behind
            lines.append(
                f"| {_cell(dep.name)} | {_cell(_installed(dep))} | {dep.ecosystem} "
                f"| {dep.latest or 'unknown'} | {behind} | {_cell(dep.license)} |"
            )
        lines.append("")
    return lines


def _vulnerabilities(result: ScanResult) -> list[str]:
    lines = ["## Vulnerabilities", ""]
    groups = [
        m
        for m in result.manifests
        if not m.error and any(d.advisories for d in m.dependencies)
    ]
    if not groups:
        lines += ["No advisories matched.", ""]
        return lines
    for manifest in groups:
        lines += [
            f"### `{_rel(manifest, result)}`",
            "",
            "| Package | Version | Advisory | Severity | Summary | Source |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        rows = [
            (advisory, dep)
            for dep in manifest.dependencies
            for advisory in dep.advisories
        ]
        rows.sort(
            key=lambda row: (
                SEVERITY_ORDER.get(row[0].severity, 9),
                row[0].id,
                row[1].name,
            )
        )
        for advisory, dep in rows:
            lines.append(
                f"| {_cell(dep.name)} | {dep.version or 'unknown'} "
                f"| [{advisory.id}]({advisory.url}) | {advisory.severity} "
                f"| {_cell(advisory.summary)} | {', '.join(advisory.sources)} |"
            )
        lines.append("")
    return lines


def _licenses(result: ScanResult) -> list[str]:
    lines = ["## Licenses", ""]
    deps = [d for m in result.manifests if not m.error for d in m.dependencies]
    flagged = [
        dep for dep in deps if _denylisted(dep.license, result.config.denylist)
    ]
    if flagged:
        listed = ", ".join(
            f"`{dep.name}@{dep.version or 'unknown'}` — {dep.license}" for dep in flagged
        )
        lines += [f"> **Denylisted licenses detected:** {listed}", ""]
    else:
        lines += ["> No denylisted licenses detected.", ""]

    groups: dict[str, set[str]] = {}
    for dep in deps:
        groups.setdefault(dep.license, set()).add(
            f"{dep.name}@{dep.version or 'unknown'}"
        )
    lines += [
        "| License | Count | Packages |",
        "| --- | --- | --- |",
    ]
    for license_id in sorted(groups, key=lambda lic: (lic == "UNKNOWN", lic)):
        packages = sorted(groups[license_id])
        lines.append(
            f"| {_cell(license_id)} | {len(packages)} | {_cell(', '.join(packages))} |"
        )
    if not deps:
        lines.append("| — | 0 | No dependencies |")
    lines.append("")
    return lines


def _configuration(config: Config) -> list[str]:
    extra = ", ".join(f"`{glob}` → {eco}" for glob, eco in config.extra_manifests.items())
    return [
        "## Configuration",
        "",
        f"- Denylisted licenses: {', '.join(f'`{x}`' for x in config.denylist) or 'none'}",
        f"- Online lookups: {'enabled' if config.online else 'disabled'}",
        f"- Cache TTL: {config.cache_ttl_hours} hours",
        f"- Additional manifest globs: {extra or 'none'}",
        f"- Allow empty: {'yes' if config.allow_empty else 'no'}",
        f"- Output: `{config.output}`",
        "",
    ]


def _installed(dep: Dependency) -> str:
    if dep.version:
        return f"{dep.version} (range)" if dep.is_range else dep.version
    return f"{dep.declared} (range)" if dep.declared else "unknown"


def _denylisted(license_id: str, denylist: list[str]) -> bool:
    return any(
        fnmatch(license_id.lower(), pattern.lower()) for pattern in denylist
    )


def _cell(value: str) -> str:
    return " ".join(str(value).replace("|", "\\|").split())


def _rel(manifest: Manifest, result: ScanResult) -> str:
    try:
        return str(Path(manifest.path).relative_to(result.target)).replace("\\", "/")
    except ValueError:
        return manifest.path
