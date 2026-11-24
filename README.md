# fact-audit

A local code audit tool that answers three questions about a project in one place: **what is risky in the code**, **what changed**, and **what it depends on**. It combines Opengrep static analysis with an LLM-written report, optional git-diff scoping, and a dependency scanner covering npm, Python and Go — behind a two-command CLI and a one-window desktop UI.

## What it does

| Stage | Command | Output |
| --- | --- | --- |
| Code audit (Opengrep + LLM) | `fact-audit <path>` | `report.md` |
| Changed files only | `fact-audit <path> --diff` | `report.md` |
| Dependency scan | `fact-audit deps <path>` | `deps-report.md` |
| Findings baseline | `fact-audit baseline <path>` | `fact-audit-baseline.json` |
| CI gate (both stages) | `fact-audit ci <path>` | `report.md`, `deps-report.md`, `fact-audit.sarif`, `.json`, `.csv` |
| Desktop UI | `fact-audit-ui` | both, in the scanned project |

The stages are independent: run one, two or all three, in any order. Each writes its own file and never touches the others' output.

## Requirements

- Python 3.13+
- [uv](https://docs.astral.sh/uv/)
- [Opengrep](https://opengrep.dev) installed for the code-audit stage
- `GROQ_API_KEY` for the LLM-written code-audit report (optional — without it, a deterministic report is written)
- Network access only when you pass `--online` to the dependency scanner

## Install

```bash
uv sync
```

Install Opengrep, the static analysis engine (a self-contained binary, not a Python package):

```powershell
irm https://raw.githubusercontent.com/opengrep/opengrep/main/install.ps1 | iex
```

On macOS and Linux, use `install.sh` from the same repository.

The code-audit stage runs `~/.opengrep/cli/latest/opengrep` when that file exists, and otherwise `opengrep` from `PATH` — so a terminal or Explorer window opened before the install can't hide it.

Create `.env` in the repository root for the code-audit stage:

```ini
GROQ_API_KEY=your-key-here
```

`.env` is git-ignored — never commit it.

## Usage

### Code audit

```bash
uv run fact-audit <project-path>
```

Runs Opengrep over the project, sends the findings to an OpenAI-compatible endpoint (Groq), and writes a Markdown report grouped by severity. Only findings present in the Opengrep JSON are reported; the model is not allowed to invent issues. Opengrep supports 30+ languages and is compatible with Semgrep rules.

Findings are normalized before reporting: `ERROR`/`WARNING`/`INFO` become `HIGH`/`MEDIUM`/`LOW` (anything else is `UNKNOWN`), the scanner's original level is kept, and confidence, CWE and OWASP metadata are carried through when the rule provides them.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--out` | `report.md` | Where to write the report |
| `--max-findings` | `50` | Cap on findings sent to the model |
| `--diff` | off | Scan only files changed against `HEAD` (requires git) |
| `--baseline` | none | Git ref to diff against; implies `--diff` |
| `--no-llm` | off | Skip the model and write the deterministic findings table |

If `GROQ_API_KEY` is missing, or the API call fails, the report falls back to a deterministic table (severity, `file:line`, rule, message) and a warning is printed. The scan never fails because the model is unavailable.

### Dependency scan

```bash
uv run fact-audit deps <project-path>          # offline, no network calls
uv run fact-audit deps <project-path> --online # advisories, latest versions, licenses
```

Writes `deps-report.md` with, in order: executive summary, manifests (and parse failures), dependency tables, vulnerabilities, licenses, and the configuration used.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--out` | `deps-report.md` | Where to write the report |
| `--online` | off | Query OSV, npm, PyPI, the Go proxy and deps.dev |
| `--config` | `<project>/.depscan.yml` | Config file to use |
| `--allow-empty` | off | Exit 0 when the project has no supported manifests |

Offline is the default and the report says so: `unknown` means *not checked*, not *no findings*.

### CI gate

```bash
uv run fact-audit ci <project-path> [--diff] [--online] [--no-llm] [--out-dir .]
```

Runs the code audit and the dependency scan in one pass and writes `report.md`, `deps-report.md`, `fact-audit.sarif`, `fact-audit.json` and `fact-audit.csv` into `--out-dir` (default: current directory). SARIF, JSON and CSV carry code findings only — dependency findings have no file or line to anchor to and stay in the Markdown report, the JSON dependency summary and the exit code.

It prints a verdict and exits non-zero when the policy is violated:

```
fact-audit: FAIL
  - 3 code finding(s) at or above ERROR
  code:         3 finding(s)
  dependencies: 1 critical, 2 high; licenses: 4 denylisted
  artifacts:    report.md, deps-report.md, fact-audit.sarif
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--diff` / `--baseline` | off / none | Gate only files changed against `HEAD` or the given ref |
| `--baseline-file` | none | Findings baseline to compare against; gates only new and reintroduced findings |
| `--update-baseline` | off | Rewrite the baseline file after a completed scan (records resolved findings) |
| `--online` | off | Look up advisories and licenses; without it vulnerability and license gates do not apply |
| `--out-dir` | `.` | Where the five artifacts are written |
| `--no-llm` | off | Deterministic report; recommended in CI (free and reproducible) |
| `--fail-on` | `error` | Fail on code findings at or above `critical`, `high`, `medium`, `low`; `error`/`warning`/`info` are aliases; `none` disables |
| `--fail-on-all` | off | Gate every finding, not only new and reintroduced ones |
| `--max-new` | none | Fail when more than N new/reintroduced findings appear (needs `--baseline-file`) |
| `--fail-on-vuln` | `high` | Fail on advisories at or above `critical`, `high`, `medium`, `low`; needs `--online` |
| `--fail-on-license` | off | Fail on denylisted licenses (the default list flags GPL/AGPL, so it is opt-in) |

`UNKNOWN` severity is never gated: an unmappable scanner level is reported, not guessed into a failure.

A stage that crashes is reported and the other still runs. No changed files and no manifests are passes, not errors.

GitHub Actions:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0        # --diff/--baseline needs the base ref
- run: uv sync
- run: uv run fact-audit ci . --diff --no-llm --fail-on error
```

Upload `fact-audit.sarif` with `github/codeql-action/upload-sarif@v3` to get inline annotations in the pull request.

### Baselines and finding lifecycle

```bash
uv run fact-audit baseline <project-path>                    # writes <project>/fact-audit-baseline.json
uv run fact-audit ci <project-path> --baseline-file <file>   # gate only new findings
uv run fact-audit ci <project-path> --baseline-file <file> --update-baseline
```

A baseline records the findings, creation time, Git revision and repository remote, so it is portable to a fresh CI checkout and can be committed. `ci` labels every current finding:

| Status | Meaning |
| --- | --- |
| `new` | not in the baseline or its resolved history |
| `existing` | recorded in the baseline and still detected |
| `reintroduced` | previously resolved and detected again |
| `resolved` | in the baseline but absent from a completed scan |

Fingerprints are `file + rule + message` with whitespace normalized and **no line number**, so moving code does not create a new finding. Identical findings in one file share a fingerprint.

`--update-baseline` rolls the baseline forward and keeps resolved fingerprints, which is what makes reintroduction detectable. It only runs when the scan completed, so a crashed or partial scan never marks findings resolved. Writes are atomic (temp file, then replace), and the file is versioned: corrupt, foreign-repository or older-fingerprint baselines are rejected with an error instead of being half-read.

The status of every finding is in `fact-audit.json` and `fact-audit.csv`, and a one-line comparison is appended to `report.md`.

### Desktop UI

```bash
uv run fact-audit-ui
```

1. **Browse** to a project folder (or paste the path).
2. Tick the stages: **Code audit**, **Changed files only**, **Dependencies**, **Online lookups**.
3. **Scan** — progress streams into the log pane and the reports are written into the selected project folder.

Scans run on a background thread, so the window stays responsive. A failing stage is logged and skipped; the other stage still completes.

### Standalone Windows executable

```bash
uv run pyinstaller fact-audit.spec --noconfirm
```

Writes `dist/fact-audit.exe` — a single file that runs without Python installed. Double-click it, or start it from a terminal.

Caveats:

- Build on Windows for Windows: PyInstaller does not cross-compile.
- The window is the Flet desktop client, which is not bundled. On first launch the exe reuses the client cached in `%USERPROFILE%\.flet\client` or downloads it (~40 MB), so that one launch needs network.
- `GROQ_API_KEY` is read from `.env` next to the exe, never from the folder you start it in.
- The code-audit stage runs `~/.opengrep/cli/latest/opengrep` if present, otherwise `opengrep` from `PATH`; Opengrep is not bundled. The dependency stage works without it.
- Reports are written into the selected project folder, not next to the exe.

## Configuration

Optional, at the scanned project's root:

```yaml
# .depscan.yml
denylist:
  - AGPL-3.0
  - GPL-3.0
  - CC-BY-NC-*
extra_manifests:
  "*.deps": python          # glob -> npm | python | go
output: deps-report.md
allow_empty: false
online: false
cache_ttl_hours: 24
```

| Key | Default | Meaning |
| --- | --- | --- |
| `denylist` | copyleft + source-available list | Licenses flagged in the report; a custom list fully replaces the default |
| `extra_manifests` | none | Additional filename globs to parse, with their ecosystem |
| `output` | `deps-report.md` | Report path; must stay inside the project (`--out` accepts any path) |
| `allow_empty` | `false` | Exit 0 when no manifests are found |
| `online` | `false` | Enable online lookups without `--online` |
| `cache_ttl_hours` | `24` | How long feed responses stay valid |

## Supported ecosystems

| Ecosystem | Files | Transitive dependencies |
| --- | --- | --- |
| npm | `package.json`, `package-lock.json` | via `package-lock.json` (v1–v3) |
| Python | `requirements.txt`, `pyproject.toml` (PEP 621) | direct declarations only |
| Go | `go.mod`, `go.sum` | via `go.sum` |

Ranges: PEP 440 ranges (`>=2.0`) are resolved to the highest satisfying release; npm ranges are resolved only when a lockfile is present. Anything unresolved keeps the declared range with a `range` marker and `unknown` for latest/behind.

Online data comes from OSV (advisories), the npm registry / PyPI / `proxy.golang.org` (latest versions) and deps.dev (licenses). Responses are cached in `~/.depscan-cache`.

## Exit codes

`fact-audit deps`:

| Code | Meaning |
| --- | --- |
| `0` | Report written |
| `1` | Bad path, missing config, no manifests without `--allow-empty`, or refusing to overwrite a file it did not create |
| `2` | Invalid arguments |

`fact-audit` (code audit only) exits `0` when the report is written, `3` when Opengrep could not run or returned unusable output, and `2` on invalid arguments. `fact-audit baseline` exits `0` when the file is written, `2` for a bad path or unwritable output, and `3` when Opengrep could not run.

`fact-audit ci`:

| Code | Meaning |
| --- | --- |
| `0` | Pass |
| `1` | Policy violated |
| `2` | Bad arguments, path or config |
| `3` | A stage failed to run (engine missing or crashed) |

`3` matters: "the scanner broke" must not look like "the code is clean".

## Tests

```bash
uv run python -m unittest discover -s tests
```

72 tests, no network required. One live-feed test is opt-in:

```powershell
$env:DEPSCAN_ONLINE_TEST="1"; uv run python -m unittest tests.test_deps.OnlineTest
```

## Limitations

- Dependency scanning is offline by default and supports only public feeds; private registries are out of scope.
- Python transitive dependencies are not resolved in this version.
- `go.sum` is best-effort and may list historical module versions; no Go toolchain is invoked.
- Vendored code (`vendor/`, `third_party/`) is skipped and only noted in the summary.
- The LLM-written code-audit report depends on the configured endpoint and `GROQ_API_KEY`; without them the report is a deterministic findings table.
- Baselines identify findings by `file + rule + message`, so identical findings in one file share a fingerprint.
- No suppression or accepted-risk files yet; use a baseline to absorb a legacy backlog. No secret or configuration scanner, and no audit database beyond the baseline file and its resolved list.
