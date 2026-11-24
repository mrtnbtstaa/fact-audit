# Feature Specification: Fact Audit — Git-Aware Security and Code Quality Auditing

**Status:** Draft  
**Version:** 1.0  
**Date:** 2026-11-23  
**Specification type:** Product / feature specification  

## 1. Overview

Fact Audit is a developer-focused auditing tool that analyzes a codebase and its Git changes, identifies security and code-quality findings, tracks those findings across audit runs, and evaluates whether the analyzed changes satisfy configurable quality and security policies.

The product must provide actionable, explainable results rather than merely forwarding raw scanner output. It should help a developer answer:

- What issues exist in this codebase?
- Which findings were introduced by this change?
- Which existing findings were fixed, reintroduced, or intentionally accepted?
- How serious and trustworthy is each finding?
- Does this change pass the configured quality gate?
- Can the results be consumed by developers, CI systems, and other security tools?

Fact Audit currently has three capabilities that this specification treats as existing behavior to preserve: a quality gate, Git diff analysis, and OpenGrep integration replacing the previous Semgrep integration. The exact implementation and current command-line interface are not prescribed here; they must be inspected before planning implementation.

## 2. Problem Statement

A scanner can report vulnerabilities, but raw findings alone do not provide enough context for a useful development workflow. Existing codebases may contain large backlogs of findings, line numbers change as code evolves, and developers need to distinguish newly introduced risks from pre-existing issues. Teams also need a consistent way to prioritize findings, document exceptions, review resolved issues, and enforce policies in local development and CI.

Fact Audit should bridge this gap by combining scanner results with Git context, stable finding identity, historical comparison, policy evaluation, and standardized reporting.

## 3. Product Goals

1. Identify security and code-quality issues in supported source files.
2. Analyze Git changes and attribute findings to changed code where possible.
3. Distinguish new, existing, resolved, reintroduced, suppressed, and accepted-risk findings.
4. Give findings consistent severity, confidence, classification, and prioritization metadata.
5. Allow projects to establish and compare against a finding baseline.
6. Enforce configurable quality gates without requiring teams to fix every legacy issue immediately.
7. Produce human-readable and machine-readable reports.
8. Support local developer workflows and automated CI execution.
9. Keep scanner integrations replaceable so the core application is not coupled to one scanning engine.
10. Make audit results reproducible, traceable, and safe to consume.

## 4. Non-Goals

The initial product is not intended to:

- Replace a full-featured commercial application security testing platform.
- Guarantee that every vulnerability or secret in a repository will be detected.
- Automatically modify or remediate source code.
- Execute untrusted application code as part of ordinary static analysis.
- Provide a hosted multi-tenant SaaS dashboard.
- Replace Git hosting platforms or their pull-request review interfaces.
- Claim exploitability solely from a scanner's severity label.
- Require AI/LLM analysis for core detection, classification, or quality-gate decisions.
- Build a distributed microservices architecture.

## 5. Users and Primary Scenarios

### User A — Individual Developer

A developer runs Fact Audit locally before committing code. They want to inspect issues in changed files, understand whether a finding is new, and receive a clear pass/fail result.

### User B — Maintainer of an Existing Codebase

A maintainer audits a repository with an existing backlog. They establish a baseline, then focus subsequent work on newly introduced findings and track remediation over time.

### User C — CI / Repository Maintainer

A maintainer runs Fact Audit in an automated pipeline. They want deterministic exit codes, machine-readable output, and a configurable policy that can prevent risky changes from being merged.

## 6. Scope and Feature Priorities

### P0 — Core audit reliability

- Preserve the current quality gate.
- Preserve Git diff analysis.
- Preserve OpenGrep as the current SAST integration.
- Normalize scanner findings into a common model.
- Generate stable finding fingerprints.
- Create, load, and compare finding baselines.
- Classify findings as new, existing, resolved, or reintroduced.
- Track finding lifecycle and history.

### P1 — Actionable security findings

- Normalize severity.
- Record confidence.
- Map findings to CWE and OWASP categories when supported by reliable rule metadata.
- Calculate transparent risk priority.
- Manage suppressions and accepted risks.
- Add secret scanning through a dedicated scanner integration.

### P2 — Interoperability and developer workflow

- Export Markdown, JSON, SARIF, and CSV reports.
- Support pre-commit usage.
- Provide GitHub Actions integration guidance and examples.
- Provide GitLab CI integration guidance and examples.
- Support branch and commit comparisons.

### P3 — Additional audit coverage

- Dependency vulnerability scanning.
- Configuration/security misconfiguration auditing.
- Historical audit summaries and trend reporting.
- Additional scanner adapters through a documented integration contract.
- Pull-request annotations where the hosting platform and CI environment support them.

Priorities describe intended delivery order, not a requirement to implement every feature in one release.

## 7. Functional Requirements

### FR-001 — Repository Audit

The system MUST allow a user to run an audit against a selected repository or project directory.

Acceptance criteria:
- The user can specify or otherwise select a repository path using the existing CLI conventions.
- The system validates that the target is accessible and reports actionable errors for invalid paths.
- The audit records the target repository and the audit execution time.
- The system does not modify source files during a normal audit.

### FR-002 — OpenGrep Static Analysis

The system MUST use OpenGrep as its current SAST scanning integration.

Acceptance criteria:
- OpenGrep findings are collected in a machine-readable form where supported.
- Scanner execution failures are distinguishable from a successful scan with zero findings.
- Missing executables, unsupported options, timeouts, and malformed output produce actionable diagnostics.
- Scanner-specific output is converted into Fact Audit's normalized finding model.
- OpenGrep-specific fields are retained when useful, without making downstream features depend on OpenGrep-only structures.

### FR-003 — Git Diff Analysis

The system MUST inspect Git changes when Git-aware auditing is requested or enabled by the current workflow.

Acceptance criteria:
- The system can identify changed, added, modified, deleted, and renamed files when Git provides that information.
- Findings can be associated with changed lines or changed files when location data is available.
- Findings outside the changed area remain distinguishable from findings introduced by the change.
- Untracked files and unavailable diff context are handled explicitly.
- A shallow clone, missing base revision, merge commit, or unavailable remote does not silently produce a misleading comparison.
- The report identifies the base and target revisions used for comparison when known.

### FR-004 — Normalized Finding Model

The system MUST convert findings from all supported scanners into a common representation.

A normalized finding SHOULD include, when available:
- Stable finding identifier / fingerprint.
- Scanner and scanner rule identifier.
- Rule name and description.
- File path and source location (line and column range).
- Severity and confidence.
- CWE identifiers and OWASP categories.
- Message, evidence, and remediation guidance supplied by the scanner or rule metadata.
- First-seen and last-seen audit references.
- Lifecycle status.
- Suppression or accepted-risk metadata.

Missing optional metadata MUST remain explicitly unknown or absent; it MUST NOT be fabricated.

### FR-005 — Finding Fingerprinting

The system MUST generate a stable fingerprint for a finding so that it can be recognized across audit runs.

Acceptance criteria:
- Fingerprints MUST not rely exclusively on line numbers.
- Fingerprinting SHOULD use stable attributes such as normalized file identity, scanner/rule identity, and relevant code or finding context.
- A line movement that does not change the underlying issue SHOULD not automatically create a new finding.
- Different issues in the same file and rule MUST not be merged merely because they share a rule identifier.
- If a finding cannot be matched confidently, the system MUST prefer an unmatched/new record over an unsafe merge.
- Fingerprint algorithm/version changes MUST be handled so existing history is not silently corrupted.

### FR-006 — Baseline Management

The system MUST allow a user to create and use a baseline representing findings known at a particular audit point.

Acceptance criteria:
- A baseline records its creation time, repository identity, revision when available, and format version.
- A later audit can compare its findings with the selected baseline.
- The comparison identifies new and previously known findings.
- Findings no longer present are reported as resolved only when the audit completed successfully and coverage is sufficient for a meaningful comparison.
- A failed or partial scan MUST NOT mark all missing findings as resolved.
- The user can explicitly choose or update the baseline through documented commands or configuration.
- Baseline files are portable and validated before use.

### FR-007 — Finding Lifecycle

The system MUST track a finding's status across audit runs.

Supported lifecycle states:
- `new`: detected for the first time relative to the selected history/baseline.
- `existing`: detected previously and still present.
- `resolved`: previously detected but absent from a successful comparable audit.
- `reintroduced`: detected again after it was previously resolved.
- `suppressed`: excluded from gate enforcement by an active suppression.
- `accepted_risk`: explicitly acknowledged and excluded or treated according to policy.

Acceptance criteria:
- Lifecycle transitions are based on recorded audit evidence.
- A finding's prior status and transition are available in reports/history.
- Suppression and accepted-risk states do not erase the underlying finding.
- A partial scan cannot incorrectly resolve findings.

### FR-008 — Severity Normalization

The system MUST map scanner-specific severity values into a common severity scale.

Default normalized levels:
- Critical
- High
- Medium
- Low
- Informational
- Unknown

Acceptance criteria:
- Mapping rules are deterministic and documented.
- Original scanner severity is retained.
- Unknown or unmappable values remain `Unknown` rather than being guessed.
- Projects can configure mappings if scanner metadata requires it.

### FR-009 — Confidence Scoring

The system SHOULD expose finding confidence when the scanner provides confidence information or when a documented deterministic mapping is available.

Acceptance criteria:
- Confidence is distinct from severity.
- Confidence values use a documented scale (for example High, Medium, Low, Unknown).
- The original scanner confidence is retained where available.
- The system MUST NOT imply that confidence is a measured probability unless it is actually calibrated as one.

### FR-010 — CWE and OWASP Classification

The system SHOULD associate findings with CWE identifiers and relevant OWASP categories when supported by scanner rule metadata or a maintained mapping.

Acceptance criteria:
- CWE identifiers are validated for expected format.
- OWASP mappings identify the taxonomy/version used.
- Unmapped findings remain unclassified rather than receiving speculative categories.
- Reports can group or filter findings by these classifications.

### FR-011 — Risk Prioritization

The system SHOULD calculate a transparent priority indicator to help users triage findings.

Acceptance criteria:
- Priority considers normalized severity and confidence at minimum.
- Additional factors, such as whether the finding is newly introduced or in changed code, may influence priority only through documented rules.
- The report explains the factors behind the assigned priority.
- Priority does not replace or overwrite the original severity.
- The algorithm is deterministic and configurable where appropriate.

### FR-012 — Quality Gate

The system MUST preserve and extend the existing quality gate.

The gate MUST support configurable policies, including:
- Fail when new findings meet or exceed a configured severity threshold.
- Fail when a specified number of new findings is exceeded.
- Fail when a specified category or rule is detected.
- Optionally evaluate all findings rather than only new findings.
- Define how unknown severity and confidence are treated.
- Define whether active suppressions and accepted risks are excluded from enforcement.

Acceptance criteria:
- Gate evaluation is deterministic for the same inputs and configuration.
- The report states pass/fail and identifies the exact policy conditions that passed or failed.
- Scanner execution errors and incomplete analysis are not silently treated as a clean pass.
- Exit codes distinguish at least successful pass, policy failure, and execution/configuration error.
- Gate policy is configurable through the project's documented configuration mechanism.

### FR-013 — Suppression Management

The system MUST support documented exceptions for findings that should not currently fail the quality gate.

Acceptance criteria:
- A suppression identifies the finding or rule and its scope.
- A suppression requires a non-empty reason.
- Suppressions can optionally include an owner and expiration date.
- Expired suppressions become active findings for gate evaluation.
- Suppressions are visible in reports and do not delete finding history.
- File-level or rule-level suppressions, if supported, are clearly distinguished from finding-specific suppressions.
- Suppression syntax and configuration are documented and validated.

### FR-014 — Accepted Risk Management

The system SHOULD allow a user to explicitly record that a finding is acknowledged and accepted as a risk.

Acceptance criteria:
- Accepted risk requires a reason and SHOULD record an owner and review/expiration date.
- Accepted risks remain visible in reports.
- Gate behavior for accepted risks is explicit and configurable.
- Expired accepted risks return to normal policy evaluation.
- Acceptance is auditable and does not imply that the underlying issue is fixed.

### FR-015 — Secret Detection

The system SHOULD support secret detection through a dedicated scanner adapter.

Acceptance criteria:
- Detection covers supported credential patterns such as API tokens, private keys, and passwords embedded in tracked files.
- Secret values MUST be redacted in console output and reports by default.
- The report identifies the file and location without unnecessarily exposing the credential.
- Scanner failures are distinguished from zero findings.
- The system does not transmit repository contents to an external service unless the user explicitly configures such a service.

### FR-016 — Dependency Vulnerability Auditing

The system MAY support dependency vulnerability scanning through a dedicated adapter.

Acceptance criteria:
- Supported package ecosystems and lockfile types are documented.
- Findings identify the affected package, installed version, advisory identifier, and fixed version when available.
- Advisory source and database/update timestamp are recorded when available.
- An unavailable advisory database is reported as incomplete analysis, not as zero vulnerabilities.
- The system does not automatically upgrade dependencies.

### FR-017 — Configuration and Misconfiguration Auditing

The system MAY support checks for insecure project or deployment configuration.

Acceptance criteria:
- Supported file types and rule sources are documented.
- Configuration findings use the normalized finding model.
- Findings include the relevant configuration path and evidence without exposing secrets.
- The system distinguishes unsupported configuration files from files that were successfully checked with no findings.

### FR-018 — Report Generation

The system MUST support human-readable and machine-readable reports.

Required formats:
- Markdown.
- JSON.
- SARIF.
- CSV.

Acceptance criteria:
- Each format represents the same underlying audit result and lifecycle classifications.
- Reports include repository/revision context, audit time, scanner execution status, summary counts, gate result, and findings.
- JSON has a documented schema/version.
- SARIF output conforms to a supported SARIF version and preserves rule/location information where available.
- CSV includes a stable header and one row per finding.
- Markdown is readable in a terminal or repository viewer.
- Sensitive values, especially detected secrets, are redacted by default.
- Report generation failure is surfaced as an execution error.

### FR-019 — Historical Audit Tracking

The system SHOULD retain or allow users to retain prior audit results for comparison.

Acceptance criteria:
- Audit records can be associated with repository identity and revision.
- Users can compare two audit records or a current audit with a baseline.
- Historical summaries show new, resolved, reintroduced, and existing finding counts.
- Retention location and deletion behavior are documented.
- History corruption or incompatible schema versions produce a clear error and do not silently discard data.

### FR-020 — Branch and Commit Comparison

The system SHOULD allow users or CI jobs to compare findings between two Git revisions or branches.

Acceptance criteria:
- The base and target revisions are explicit.
- Missing revisions and unavailable Git history are reported clearly.
- The comparison distinguishes findings introduced, removed, and unchanged.
- Rename and move handling follows the documented Git diff behavior.

### FR-021 — Pre-commit Workflow

The system SHOULD be usable as a pre-commit check.

Acceptance criteria:
- Developers can configure a command or hook to audit staged changes.
- Only staged changes are considered for changed-code gating when staged mode is selected.
- Unstaged changes are not accidentally represented as staged content.
- The hook returns a non-zero status when the configured gate fails.
- Hook installation is optional and documented; normal Git operations remain available if the hook is not installed.

### FR-022 — CI Integration

The system SHOULD provide documented integration for GitHub Actions and GitLab CI.

Acceptance criteria:
- CI examples install or locate required scanner executables and run Fact Audit reproducibly.
- CI jobs can select base and target revisions.
- CI jobs can upload or publish supported reports as artifacts.
- The quality gate controls job success or failure through documented exit codes.
- Tokens and credentials are not printed in logs.
- CI behavior is consistent with local execution given equivalent inputs and configuration.

### FR-023 — Pull Request / Merge Request Annotations

The system MAY provide annotations for findings in GitHub pull requests or GitLab merge requests through CI integrations.

Acceptance criteria:
- Annotations point to valid changed-file locations when the platform supports them.
- Findings without a valid changed-line location remain in the report but are not assigned a fabricated annotation location.
- Annotation publishing is optional and requires explicit CI configuration and permissions.

### FR-024 — Scanner Adapter Extensibility

The system MUST keep scanner integrations behind a stable internal contract.

Acceptance criteria:
- Scanner-specific execution and parsing are isolated from core lifecycle, baseline, gate, and reporting behavior.
- Each adapter declares its name, supported capabilities, version information, and execution status.
- Adapter output is normalized before policy evaluation.
- A scanner can be added without rewriting the baseline or report-generation logic.
- Unsupported capabilities are reported clearly.

### FR-025 — Audit Summary and Trends

The system SHOULD provide concise summaries and trend information from retained audit history.

Acceptance criteria:
- Summaries include counts by severity and lifecycle status.
- Trends can show whether findings are increasing, decreasing, or unchanged across comparable audits.
- Comparisons identify incomplete or non-comparable audit runs.
- Trend output does not imply improvement when scan coverage has decreased.

## 8. User Stories and Acceptance Scenarios

### US-001 — Audit a repository

As a developer, I want to scan a repository so that I can identify security and code-quality issues.

**Scenario: Successful scan**
- Given a valid repository and an available OpenGrep executable
- When I run an audit
- Then Fact Audit executes the configured checks
- And normalizes the findings
- And generates the requested report
- And reports the quality-gate result.

**Scenario: Scanner unavailable**
- Given OpenGrep is required but unavailable
- When I run an audit
- Then Fact Audit reports the missing dependency
- And does not report the repository as clean.

### US-002 — Audit only changes

As a developer, I want to focus on changed code so that I can understand the risks introduced by my work.

**Scenario: New issue in changed code**
- Given a valid base and target revision
- And a finding exists on a changed line in the target revision
- When I run Git-aware analysis
- Then the finding is classified as new when it is absent from the comparison baseline
- And the report identifies its changed-file location.

**Scenario: Existing issue outside the diff**
- Given a finding exists outside the changed lines
- When I run Git-aware analysis
- Then the finding remains visible as an existing/out-of-diff finding
- And it is not incorrectly described as introduced by the change.

### US-003 — Establish a baseline

As a maintainer, I want to save existing findings as a baseline so that future gates focus on regressions.

**Scenario: Baseline comparison**
- Given a successfully completed audit
- When I save its findings as a baseline
- And a later audit detects one additional finding
- Then the additional finding is classified as new
- And unchanged findings are classified as existing.

**Scenario: Incomplete scan**
- Given a baseline contains findings
- And a later scan fails for one required scanner
- When the comparison runs
- Then missing findings are not automatically marked resolved
- And the report indicates incomplete analysis.

### US-004 — Track remediation

As a maintainer, I want to know which findings were fixed or reintroduced.

**Scenario: Finding resolved**
- Given a finding exists in a prior successful audit
- When a comparable later audit completes successfully and no longer detects it
- Then the finding is classified as resolved.

**Scenario: Finding reintroduced**
- Given a finding was previously resolved
- When a later audit detects the same fingerprint
- Then it is classified as reintroduced.

### US-005 — Enforce a quality gate

As a repository maintainer, I want configurable gate policies so that risky changes can fail CI.

**Scenario: New high-severity finding**
- Given the policy fails on new High or Critical findings
- And the audit detects a new High finding
- When the gate is evaluated
- Then the gate fails
- And the report identifies the finding and policy condition.

**Scenario: No policy violation**
- Given the audit completed successfully
- And no finding violates the configured policy
- When the gate is evaluated
- Then the gate passes.

### US-006 — Suppress a false positive

As a developer, I want to document a false positive so that it does not repeatedly fail the gate.

**Scenario: Active suppression**
- Given a finding has a valid suppression reason and an unexpired suppression
- When the gate is evaluated
- Then the finding is marked suppressed
- And its existence remains visible in the report.

**Scenario: Expired suppression**
- Given a finding's suppression has expired
- When the gate is evaluated
- Then the finding is evaluated under the normal policy.

### US-007 — Export results

As a developer or CI system, I want standardized reports so that results can be reviewed and consumed by other tools.

**Scenario: SARIF export**
- Given a completed audit with findings
- When I request SARIF output
- Then Fact Audit produces a valid SARIF document
- And includes available rule and location metadata.

### US-008 — Run in CI

As a maintainer, I want Fact Audit to run in CI so that every proposed change is checked consistently.

**Scenario: CI gate failure**
- Given the CI job runs Fact Audit with a configured gate
- And a new finding violates the policy
- When the audit completes
- Then Fact Audit returns the documented policy-failure exit code
- And CI marks the job as failed.

## 9. Quality Attributes / Non-Functional Requirements

### NFR-001 — Determinism

Given the same repository state, scanner versions, configuration, baseline, and inputs, normalization, lifecycle comparison, and gate evaluation SHOULD produce equivalent results.

### NFR-002 — Performance

Fact Audit SHOULD avoid unnecessary full-repository work when a changed-file or changed-line mode can safely narrow the analysis. Any optimization MUST preserve documented correctness and must not silently omit required checks.

### NFR-003 — Reliability

A scanner crash, timeout, malformed output, or partial scan MUST be represented as an execution/coverage problem. It MUST NOT be interpreted as a clean scan.

### NFR-004 — Portability

The core workflow SHOULD work on supported Windows, Linux, and macOS environments, subject to scanner availability and documented platform constraints.

### NFR-005 — Security and Privacy

- Repository source and findings remain local by default.
- No source content is transmitted to third-party services unless explicitly configured by the user.
- Secrets are redacted from logs and reports by default.
- Baseline and history files do not contain raw secret values.
- Paths and report content are handled safely; untrusted repository content is treated as data, not executable instructions.

### NFR-006 — Maintainability

Scanner adapters, finding normalization, lifecycle tracking, gate evaluation, and report generation MUST have clear boundaries and independently testable behavior.

### NFR-007 — Backward Compatibility

Existing command-line behavior and configuration SHOULD remain compatible where practical. Breaking changes MUST be documented with migration guidance.

### NFR-008 — Explainability

Every gate failure and risk-priority result MUST include enough information to explain which finding and policy caused the result.

### NFR-009 — Data Integrity

Baseline and history updates SHOULD be written atomically. A failed write MUST not leave a partially written baseline that appears valid.

## 10. Configuration Requirements

Fact Audit MUST provide a documented configuration mechanism for project-level behavior. The exact filename and schema are implementation decisions for the plan phase.

Configuration SHOULD cover:
- Scanner enablement and executable configuration.
- Git base/target revisions and changed-code behavior.
- Severity and confidence mapping.
- Quality-gate thresholds and categories.
- Baseline location and comparison behavior.
- Suppression and accepted-risk policy.
- Report formats and output destinations.
- Optional secret, dependency, and configuration scanners.
- History retention behavior.

Invalid configuration MUST produce a clear error that identifies the problematic setting. Defaults MUST be documented. Secrets MUST not be required in plaintext configuration files.

## 11. Data and State Requirements

The system needs to represent at least these conceptual records:

### Audit Run

- Unique audit identifier.
- Repository identity/path.
- Start and completion timestamps.
- Commit/base/target revisions when available.
- Scanner versions and execution statuses.
- Coverage/completeness status.
- Summary and gate result.
- Reference to the normalized findings produced.

### Finding

- Stable fingerprint and fingerprint version.
- Scanner/rule identity.
- Normalized and original severity.
- Confidence.
- Classification metadata.
- File and source location.
- First-seen/last-seen audit references.
- Lifecycle state and transition history.

### Baseline

- Schema version.
- Repository identity.
- Creation timestamp and source revision.
- Fingerprint algorithm version.
- Findings included in the snapshot.

### Exception

- Finding/rule/file scope.
- Exception type: suppression or accepted risk.
- Required reason.
- Optional owner.
- Creation and expiration/review dates.
- Status and history.

The storage technology and exact serialization format are intentionally deferred to `plan.md`.

## 12. Error Handling and Edge Cases

The system MUST explicitly handle:

1. OpenGrep is not installed or cannot be found on PATH.
2. OpenGrep exits unsuccessfully or returns malformed output.
3. A scanner times out or is interrupted.
4. The repository is not a Git repository.
5. The working tree has staged, unstaged, and untracked changes simultaneously.
6. The base revision does not exist locally.
7. A file is renamed or moved between revisions.
8. A finding has no line number or has an invalid location.
9. A scanner changes its rule identifier or output schema.
10. A fingerprint matches multiple candidate findings.
11. The baseline is corrupt, incompatible, or belongs to another repository.
12. A scan is partial and cannot safely establish resolution.
13. A suppression is malformed, expired, or missing a reason.
14. A secret is detected and must be redacted.
15. A report destination is not writable.
16. A dependency advisory source is unavailable.
17. A source file is binary, generated, ignored, or unsupported.
18. The repository contains a very large number of findings.
19. A user requests a report format that cannot represent some scanner metadata.
20. Historical data uses an older schema or fingerprint version.

## 13. Success Criteria

The feature is successful when:

- Existing quality-gate, Git diff, and OpenGrep workflows continue to work.
- A successful audit produces normalized findings and clearly reports scanner coverage.
- A baseline comparison reliably distinguishes new, existing, resolved, and reintroduced findings in supported scenarios.
- Line movement alone does not routinely create duplicate findings.
- Incomplete scans never silently mark findings resolved or pass as clean.
- Gate results are deterministic and explainable.
- Suppressions and accepted risks are traceable, reasoned, and time-aware.
- Markdown, JSON, SARIF, and CSV reports are generated consistently.
- CI can fail on policy violations using documented exit codes.
- Scanner integrations can be extended without rewriting core finding lifecycle and reporting behavior.
- Secret values are redacted by default.

## 14. Assumptions and Open Questions

These points must be verified against the existing repository before implementation planning:

1. Fact Audit is currently a local developer tool with a CLI; confirm its current command structure.
2. The existing quality gate and Git diff behavior are already implemented; inspect their actual semantics and tests.
3. OpenGrep is the intended SAST engine going forward; confirm supported version and output format.
4. Determine whether current reports are Markdown-only or whether other formats already exist.
5. Decide whether baseline/history storage should be repository-local, user-local, or configurable.
6. Decide whether the initial baseline is generated explicitly by the user or can be initialized automatically.
7. Define the minimum supported Python and operating-system versions based on the current project.
8. Select the secret-scanning and dependency-scanning engines only during planning after evaluating licensing, platform support, output formats, and maintenance status.
9. Decide whether GitHub/GitLab annotations belong in the first integration milestone or a later release.
10. Define whether accepted-risk exceptions require an owner and mandatory expiration in all projects or are configurable.
11. Confirm which OpenGrep rulesets and language coverage are expected; language support depends on the selected rules and scanner capabilities.
12. Decide the supported SARIF version and validate interoperability with the intended code-scanning consumers.

## 15. Out of Scope for This Specification

This document does not prescribe:
- A specific Python package/module layout.
- A database or persistence technology.
- A specific CLI framework.
- A specific secret or dependency scanner.
- A detailed internal class diagram.
- Exact command names or configuration key names.
- A specific CI vendor implementation beyond the required integration outcomes.

Those decisions belong in the implementation plan after inspecting the current Fact Audit codebase.

## 16. Definition of Done

A feature is considered complete only when:

- Its functional requirements are implemented and covered by automated tests.
- Acceptance scenarios pass.
- Failure and partial-analysis behavior is tested.
- User-facing configuration and CLI behavior are documented.
- Reports and schemas are versioned where applicable.
- Existing workflows have regression tests.
- Security-sensitive output is checked for accidental secret disclosure.
- The implementation does not claim successful analysis when required scanners or comparisons did not complete.
