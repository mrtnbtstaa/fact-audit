# Feature Specification: Dependency Scanning
**Feature Branch**: `dependency-scanning`
**Created**: 2026-11-21
**Status**: Draft
**Input**: User description: "Add dependency scanning as a new improvement. The scanner reads a target project, analyzes its declared and transitive dependencies, and emits `report.md` summarizing what it finds. Current feature set is semgrep + git diff; this is the next improvement."

---

## Context

This specification describes a single, self-contained improvement to the existing analysis pipeline: **dependency scanning**. The pipeline today exposes two capabilities — `semgrep` (static rules) and `git diff` (change inspection). Dependency scanning is added as a third capability that, like the others, takes a target project path and produces a Markdown report.

The deliverable produced by this feature is `report.md`. It is a human-readable document that describes **what the scanner found in the scanned project**: every manifest it located, the dependency inventory it built, the vulnerabilities it matched, the licenses it detected, and a short executive summary at the top.

This spec follows the spec-kit `spec-template.md` structure (https://github.com/github/spec-kit/blob/main/templates/spec-template.md). It defines the **what** and the **why**. Technical choices (language, scanner library, vulnerability feed source, etc.) are intentionally deferred to the follow-on `plan.md` step, per spec-kit's Spec-Driven Development convention.

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Scan a project and get a readable report (Priority: P1)

A developer runs the dependency scanner against a project directory. The scanner walks the directory tree, locates dependency manifests for the ecosystems it supports, parses them, resolves transitive dependencies where possible, and writes `report.md` to the project root (or an output directory). The developer opens `report.md` and can read, top to bottom: how many manifests were found, how many dependencies were enumerated, how many advisories matched, and a per-manifest breakdown of each dependency with its version, source, license, and any matched vulnerability.

**Why this priority**: This is the core happy path. Without it, the feature has no value. Every other user story depends on this producing a credible `report.md`.

**Independent Test**: Point the scanner at a fixture project containing one `package.json` with a single known-vulnerable dependency (e.g., an old `lodash` version with a published GHSA). Run the scanner. Assert that `report.md` exists, that the executive summary line counts ≥ 1 advisory, and that the per-dependency table for that manifest lists the vulnerable package with its CVE/GHSA identifier and severity.

**Acceptance Scenarios**:
1. **Given** a project directory containing at least one supported manifest file, **When** the scanner runs against that path, **Then** a `report.md` file is written containing an executive summary, a manifests section, a dependencies section, a vulnerabilities section, a licenses section, and a "no findings" footer for each empty category.
2. **Given** a project directory containing zero supported manifest files, **When** the scanner runs, **Then** `report.md` is still written and its body states "No supported dependency manifests were found in <path>." with a list of the file extensions the scanner looked for.
3. **Given** a project directory with multiple ecosystems side by side (e.g., a monorepo with `package.json` and `requirements.txt`), **When** the scanner runs, **Then** each manifest is reported under its own subsection and the executive summary tallies are aggregated across all of them.

---

### User Story 2 - Surface vulnerable dependencies with severity and advisory ID (Priority: P1)

A security-minded reviewer opens `report.md` and wants to see, in under 30 seconds, whether any of the project's dependencies have a known advisory. The vulnerabilities section lists every matched advisory grouped by manifest, with: package name, installed version, advisory ID (CVE or GHSA), severity (Critical / High / Medium / Low), a one-line summary, and a link to the advisory source. Critical and High entries appear first within each manifest's group.

**Why this priority**: Vulnerability detection is the highest-value signal the scanner produces. A reader who looks at nothing else in `report.md` should be able to answer "do I have a known-bad dependency?" from this section alone.

**Independent Test**: Build a fixture project with one manifest containing exactly two dependencies — one with a published Critical advisory and one with no known advisory. Run the scanner. Assert that the vulnerabilities section lists exactly one entry, that its severity is `Critical`, and that the other dependency is listed in the dependencies section but absent from the vulnerabilities section.

**Acceptance Scenarios**:
1. **Given** a manifest pins a package version that has one or more published advisories, **When** the scanner runs, **Then** the vulnerabilities section lists one row per matched advisory and each row includes package name, installed version, advisory ID, severity, one-line summary, and a clickable link.
2. **Given** a manifest contains a vulnerable package but the installed version is above the patched range, **When** the scanner runs, **Then** the package does **not** appear in the vulnerabilities section and does appear in the dependencies section with its resolved version noted.
3. **Given** multiple advisories of mixed severity apply to the same package, **When** the scanner runs, **Then** all advisories are listed and ordered within that manifest's group by severity (Critical → High → Medium → Low), then alphabetically by advisory ID.

---

### User Story 3 - Detect and report license information per dependency (Priority: P2)

A maintainer wants to know what licenses they are pulling in, to catch copyleft or non-permissive licenses before they ship. The licenses section of `report.md` lists every dependency with its detected SPDX identifier (or `UNKNOWN` if it could not be determined), grouped by license. A short callout at the top of the section flags any license on a configurable denylist (default: `AGPL-3.0`, `GPL-3.0`, `GPL-2.0`, `CC-BY-NC-*`, `SSPL`, `BUSL-*`, `Elastic-2.0`).

**Why this priority**: License compliance is a frequent reason to add dependency scanning, but it is a smaller population of readers than the vulnerability audience and the signal is less urgent than an active CVE.

**Independent Test**: Build a fixture project with one manifest containing three packages with three different known licenses (e.g., MIT, Apache-2.0, GPL-3.0). Run the scanner with the default denylist. Assert that the licenses section lists all three SPDX identifiers, that GPL-3.0 is called out at the top of the section, and that the other two are not.

**Acceptance Scenarios**:
1. **Given** a manifest declares a package whose published license is one of the denylisted identifiers, **When** the scanner runs, **Then** the licenses section opens with a "Denylisted licenses detected" callout that names the package, its version, and the matched license.
2. **Given** a manifest declares a package whose license cannot be determined from available metadata, **When** the scanner runs, **Then** the package is listed under an `UNKNOWN` license group and counted in the executive summary's "unknown licenses" tally.
3. **Given** the user passes a custom denylist via configuration (e.g., only `MIT`), **When** the scanner runs, **Then** only licenses on that custom list are called out and the default denylist is fully overridden (not merged).

---

### User Story 4 - Flag outdated dependencies (Priority: P3)

A developer wants to know which dependencies are behind their latest stable release. The dependencies section includes a "Latest" column showing the newest stable version published in the package registry, and a "Behind" column showing `major`, `minor`, or `patch` based on the SemVer distance. Dependencies more than one major version behind are highlighted.

**Why this priority**: Useful signal, but lower urgency than vulnerabilities or licenses — a developer can obtain this from `npm outdated` / `pip list --outdated` directly. It is included to make `report.md` a single source of truth, not because it cannot be obtained elsewhere.

**Independent Test**: Build a fixture project pinning one package at a version exactly one major behind the current latest stable release and one package at the current latest. Run the scanner. Assert that the first package's "Behind" column reads `major` and is highlighted, and the second's reads `current`.

**Acceptance Scenarios**:
1. **Given** a manifest pins a package at a version older than the latest stable release, **When** the scanner runs, **Then** the dependencies section shows the installed version, the latest version, and a `Behind` column with `major` / `minor` / `patch`.
2. **Given** the installed version equals the latest stable version, **When** the scanner runs, **Then** the `Behind` column reads `current` and the row is not highlighted.
3. **Given** the latest version cannot be determined (offline, private registry, unknown package), **When** the scanner runs, **Then** the `Latest` and `Behind` columns read `unknown` and no highlight is applied.

---

### User Story 5 - Run alongside semgrep + git diff without breaking them (Priority: P1)

A developer who today runs `semgrep` and `git diff` against a project adds this scanner to their workflow. The new scanner does not modify the target project (read-only), does not share state with the semgrep or git-diff stages, and produces its own `report.md` whose filename does not collide with any existing output file. The developer can run all three in any order without one affecting another's output.

**Why this priority**: A new improvement that breaks the existing pipeline is a regression. This guards non-interference and is required for the feature to ship.

**Independent Test**: Capture the outputs of `semgrep` and `git diff` against a fixture project. Run the dependency scanner against the same fixture. Re-run `semgrep` and `git diff` and assert byte-equal outputs to the captured baselines. Assert that the dependency scanner's output file is `report.md` and does not overwrite any semgrep or git-diff artifact.

**Acceptance Scenarios**:
1. **Given** the existing semgrep stage produces `semgrep.sarif` and the git-diff stage produces `diff.txt`, **When** the dependency scanner runs in the same project, **Then** both existing files are unchanged and `report.md` is added.
2. **Given** the dependency scanner is invoked while the target project is mid-edit by another tool, **When** the scanner runs, **Then** it opens files read-only, does not write inside the target project tree (except its own `report.md` if configured to write there), and exits cleanly.
3. **Given** the developer runs the dependency scanner before, after, or interleaved with semgrep and git diff, **When** all three have completed, **Then** each tool's output file is present and unchanged by the others.

---

### Edge Cases

- **What happens when a manifest is malformed (e.g., truncated JSON, syntactically invalid TOML)?** The scanner records the file under a "Parse failures" subsection of the manifests section, includes the parse error message and line number if available, and continues scanning the rest of the project. `report.md` is still produced.
- **What happens when the same package appears in multiple manifests (e.g., a monorepo with the same dependency declared in several `package.json` files)?** Each occurrence is reported under its own manifest's subsection, and the executive summary notes the count of unique packages separately from the count of total declarations.
- **What happens when a manifest declares a private or registry-scoped package that cannot be resolved against a public feed?** The package is listed in the dependencies section with `Latest` and `Behind` set to `unknown`, no advisory lookup is attempted against it, and its license is recorded as `UNKNOWN` unless declared in the manifest itself.
- **What happens when the target path is not a directory (file, symlink to nowhere, nonexistent)?** The scanner exits non-zero with a clear single-line error to stderr and does not write `report.md`.
- **What happens when two advisories with the same ID are matched against the same package via two different feeds?** The vulnerability appears once in the report; the "Source" column lists every feed that matched it.
- **What happens when a manifest uses a non-pinned version range (e.g., `^1.2.3`, `>=2.0.0`)?** The scanner resolves the highest version satisfying the range that is actually installable from the registry snapshot and reports that as the "installed version", with a `range` marker next to it so the reader knows it was not a pinned version.
- **What happens when the scanned project contains vendored dependencies (e.g., checked-in `vendor/` directories)?** Vendored dependencies are out of scope for v1. The scanner notes in the executive summary that vendored code was detected (if a `vendor/` directory is present) but does not enumerate packages inside it.

---

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The scanner MUST accept a target project path as input and walk that path recursively to locate supported dependency manifests.
- **FR-002**: The scanner MUST support, at minimum, the following manifest file types in v1: `package.json` and `package-lock.json` (npm), `requirements.txt` and `pyproject.toml` (Python), and `go.mod` (Go). Other ecosystems are out of scope for v1.
- **FR-003**: The scanner MUST be read-only with respect to the target project. The only file it MAY write inside the target tree is `report.md`, and only when the user has configured output to be co-located.
- **FR-004**: The scanner MUST write its findings to a Markdown file named `report.md`. The output path is configurable; the default is the current working directory.
- **FR-005**: `report.md` MUST contain, in order: (a) a title and generation timestamp, (b) an executive summary, (c) a manifests section, (d) a dependencies section, (e) a vulnerabilities section, (f) a licenses section, (g) a configuration appendix listing the denylist and any non-default options used.
- **FR-006**: The executive summary MUST include the following counts: manifests found, manifests parsed successfully, manifests that failed to parse, total dependency declarations, unique dependencies, dependencies with at least one matched advisory, advisories by severity (Critical / High / Medium / Low), dependencies with unknown license, and dependencies behind by ≥ 1 major version.
- **FR-007**: For every matched advisory, the vulnerabilities section MUST include: package name, installed version, advisory identifier (CVE or GHSA), severity, one-line summary text, and a link to the advisory source.
- **FR-008**: For every dependency enumerated, the dependencies section MUST include: package name, installed (or resolved) version, ecosystem, latest stable version (or `unknown`), `Behind` marker (`current` / `patch` / `minor` / `major` / `unknown`), and license SPDX identifier (or `UNKNOWN`).
- **FR-009**: The licenses section MUST group dependencies by SPDX identifier, list the count per group, and open with a callout naming any dependency whose license is on the configured denylist.
- **FR-010**: The scanner MUST NOT modify, delete, or rename any file produced by the existing `semgrep` or `git diff` stages.
- **FR-011**: The scanner MUST exit with a non-zero status code when the target path does not exist, is not a directory, or no supported manifests are found AND the user has not passed the `--allow-empty` flag.
- **FR-012**: The scanner MUST handle parse failures gracefully: a malformed manifest is recorded under "Parse failures" in the manifests section, and the scanner continues processing other manifests in the same run.
- **FR-013**: The scanner MUST deduplicate advisories matched from multiple feeds so the same CVE/GHSA appears at most once per (package, version) pair, with all matching feed sources listed in a single row.
- **FR-014**: The scanner MUST resolve transitive dependencies for npm (via `package-lock.json` when present) and for Go (via `go.sum` when present). For Python, only direct declarations in `requirements.txt` / `pyproject.toml` are enumerated in v1; transitive resolution for Python is deferred.
- **FR-015**: The scanner MUST support a configuration file (default: `.depscan.yml` in the project root, overridable via `--config`) specifying: denylisted licenses, additional manifest globs, an output path, and an `allow-empty` flag.
- **FR-016**: `report.md` MUST be deterministic in structure for the same input: section order, table columns, and ordering rules (severity then ID for vulnerabilities; alphabetical by package within each manifest for dependencies) MUST NOT vary between runs against the same project state.
- **FR-017**: The scanner MUST NOT make outbound network calls unless advisory and latest-version lookups are explicitly enabled via configuration (`--online` or `online: true` in the config). In offline mode, the `Latest`, `Behind`, and vulnerability columns MUST read `unknown` / `not checked`, and the executive summary MUST note that the run was offline.
- **FR-018**: When online lookups are enabled, the scanner MUST cache responses in a local cache directory (default: `.depscan-cache/` under the user's home directory) with a configurable TTL (default 24 hours) and MUST re-use cached entries on subsequent runs against the same packages.
- **FR-019**: The scanner MUST treat the existing `semgrep` and `git diff` stages as opaque. It MUST NOT import their internals, depend on their output files, or be required to run after them. The dependency scanner is independently invocable.
- **FR-020**: The scanner MUST emit a single-line progress indicator to stderr while running (one line per manifest processed), and MUST NOT emit anything to stdout other than the final path of the written `report.md`.

*Items requiring clarification before plan.md:*
- **FR-021**: The scanner MUST integrate with the existing pipeline as [NEEDS CLARIFICATION: a separately invoked command, or a subcommand of the existing CLI? The user mentioned "the current feature is semgrep + git diff" but did not specify whether these are subcommands of one CLI or three independent binaries. Affects invocation and help-text conventions.]
- **FR-022**: The scanner MUST produce `report.md` in the same output directory as the existing semgrep and git-diff outputs by default when [NEEDS CLARIFICATION: the existing tools write to a shared output directory. The location of that directory is not specified in the user's message and must be confirmed before the plan step.]

### Key Entities *(include if feature involves data)*

- **Manifest**: A single dependency declaration file discovered in the target project. Key attributes: absolute path, ecosystem (npm / python / go), parse status (ok / failed), parse error message (if failed), and a list of declared dependencies.
- **Dependency**: A single package declared in or resolved from a manifest. Key attributes: name, ecosystem, declared version specifier, resolved installed version, latest stable version, behind marker, source feed (npm registry / PyPI / Go proxy / unknown), and license SPDX identifier.
- **Advisory**: A published vulnerability record matched against a dependency. Key attributes: advisory ID (CVE or GHSA), affected package, affected version range, severity (Critical / High / Medium / Low), one-line summary, source feed (OSV / GitHub Advisory Database / NVD), and canonical URL.
- **License**: An SPDX identifier detected for a dependency. Key attributes: SPDX identifier, on-denylist flag, and the package(s) it applies to.
- **ScanResult**: The top-level aggregate produced by one scanner run. Key attributes: target path, run timestamp, online/offline flag, list of manifests, list of dependencies, list of advisories, and the configuration snapshot used. `report.md` is the serialized view of a `ScanResult`.

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Running the scanner against a fixture project containing 10 manifests across the 3 supported ecosystems completes in under 15 seconds on a warm cache in offline mode.
- **SC-002**: Running the scanner against a fixture project containing one known-vulnerable dependency produces a `report.md` whose vulnerabilities section lists that dependency and its advisory ID within the first 5 rows of the section.
- **SC-003**: A reader who opens `report.md` and reads only the executive summary can correctly answer "how many vulnerable dependencies does this project have, and how severe are they?" without scrolling further. Validated by a 5-minute review with a developer not involved in building the scanner.
- **SC-004**: Running the scanner immediately before and immediately after running the existing `semgrep` and `git diff` stages produces byte-identical semgrep and git-diff outputs (i.e., zero interference).
- **SC-005**: Running the scanner twice in a row against the same project state produces byte-identical `report.md` content except for the generation timestamp line.
- **SC-006**: The scanner correctly handles a fixture project with a deliberately malformed manifest (truncated JSON) by recording it under "Parse failures" and continuing to scan the remaining 9 manifests without aborting.
- **SC-007**: In offline mode, the scanner completes against a 50-dependency fixture project in under 10 seconds and `report.md` clearly states in the executive summary that the run was offline, so the reader does not mistake `unknown` "Latest" / "Behind" / vulnerability columns for "no findings".
- **SC-008**: `report.md` for a project with zero vulnerabilities still renders the vulnerabilities section with a clearly visible "No advisories matched." message, so an empty section is never confused with a missing section.

---

## Assumptions

- The existing `semgrep` and `git diff` stages are stable, documented, and produce output files at known paths. The dependency scanner does not need to know those paths, only that its own output filename (`report.md`) does not collide with them.
- The target project is readable by the user invoking the scanner. Permission errors on individual files inside the target tree are logged and skipped; they do not abort the run.
- The user has network access on the machine where the scanner runs when `--online` is used. The scanner does not implement proxy configuration in v1; if a corporate proxy is required, the user sets the standard `HTTP_PROXY` / `HTTPS_PROXY` environment variables and the scanner's HTTP client honors them.
- Vulnerability and latest-version data come from public feeds (OSV / GitHub Advisory Database / npm registry / PyPI / Go proxy). No private feeds are supported in v1.
- The scanner is invoked manually or by a CI step. It does not schedule itself, watch the filesystem, or run as a daemon in v1.
- Vendored dependencies (checked-in source under `vendor/`, `third_party/`, etc.) are out of scope for v1. If a `vendor/` directory is detected, the executive summary notes its presence but does not enumerate it.
- Lockfile parsing is best-effort: if `package-lock.json` or `go.sum` is present, transitive dependencies are enumerated from it; if absent, only direct declarations are reported.
- The default denylist of licenses reflects common open-source compliance concerns (copyleft and source-available licenses). It is overridable per project via configuration and is not a policy statement.
- This spec covers the **what** and the **why** only, per spec-kit's Spec-Driven Development convention. Technical decisions — implementation language, HTTP client, caching format, Markdown rendering library, advisory feed choice, CLI argument parser — are intentionally deferred to the follow-on `plan.md` produced by the `/speckit-plan` step.
