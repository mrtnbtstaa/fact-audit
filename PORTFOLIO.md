# fact-audit — portfolio

## OVERVIEW

fact-audit is a local code audit tool built to make a project's risk readable before it ships: what is dangerous in the code, what changed on this branch, and what the project depends on.

It combines three workflows — Semgrep static analysis with an AI-written report, git-diff scoping, and dependency scanning across npm, Python and Go — behind one CLI and a one-window desktop UI. The interesting constraint is trust: the scanner is read-only, makes no network calls unless asked, refuses to overwrite another stage's output, and produces a deterministic report where only the timestamp may change. A malformed manifest or a dead feed degrades one row, never the run.

I built it solo in Python, keeping the dependency footprint to Semgrep, the OpenAI client, Flet, PyYAML and packaging, with the rest on the standard library — urllib for feeds, tomllib for pyproject, a content-addressed cache for repeat runs. Parsing, network lookups and Markdown rendering live in separate modules so the offline path never imports the network layer. The result is a cross-platform tool with a unittest suite covering parsing, exit codes, determinism and byte-level non-interference with the existing stages, plus an opt-in live-feed test.

## FEATURES

**01** **Static Audit Report.** Run Semgrep over a whole project, or only over files changed against `HEAD`, and get a severity-grouped Markdown report written by an LLM constrained to the findings JSON — no invented issues, one-line fixes, a configurable cap on findings.

**02** **Dependency Inventory.** Walk the tree for `package.json`, `package-lock.json`, `requirements.txt`, `pyproject.toml`, `go.mod` and `go.sum`, pruning `node_modules` and virtualenvs. Transitive packages come from lockfiles, PEP 440 ranges resolve to the highest satisfying release, and monorepos report each manifest separately.

**03** **Vulnerability Matching.** Every resolved package is checked against OSV for CVEs and GHSAs with severity, a one-line summary and a link. Duplicate records for the same issue collapse into one row, ordered Critical to Low, so the worst finding is never below the fold.

**04** **License and Freshness.** SPDX licenses are grouped per dependency with a callout for anything on a configurable copyleft denylist. Latest stable versions come from the npm registry, PyPI and the Go proxy, with a SemVer distance of `current`, `patch`, `minor` or `major` — bolded when a major version behind, `unknown` when offline.

**05** **One-Window UI.** Pick a folder, tick code audit, changed files only, dependencies and online lookups, then scan. Work runs off the UI thread with live progress, reports land in the selected project, and a failing stage is logged without blocking the other.
