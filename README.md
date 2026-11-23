# fact-audit

A local code audit tool that answers three questions about a project in one place: **what is risky in the code**, **what changed**, and **what it depends on**. It combines Opengrep static analysis with an LLM-written report, optional git-diff scoping, and a dependency scanner covering npm, Python and Go — behind a two-command CLI and a one-window desktop UI.

## What it does

| Stage | Command | Output |
| --- | --- | --- |
| Code audit (Opengrep + LLM) | `fact-audit <path>` | `report.md` |
| Changed files only | `fact-audit <path> --diff` | `report.md` |
| Dependency scan | `fact-audit deps <path>` | `deps-report.md` |
| Desktop UI | `fact-audit-ui` | both, in the scanned project |

The stages are independent: run one, two or all three, in any order. Each writes its own file and never touches the others' output.

## Requirements

- Python 3.13+
- [uv](https://docs.astral.sh/uv/)
- [Opengrep](https://opengrep.dev) installed for the code-audit stage
- `GROQ_API_KEY` for the code-audit stage (the dependency scanner works without it)
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

| Flag | Default | Meaning |
| --- | --- | --- |
| `--out` | `report.md` | Where to write the report |
| `--max-findings` | `50` | Cap on findings sent to the model |
| `--diff` | off | Scan only files changed against `HEAD` (requires git) |

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
- `GROQ_API_KEY` is read from `.env` in the directory the exe is started from. Put `.env` next to the exe, or start the exe from the folder that contains it.
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
| `output` | `deps-report.md` | Output path (relative to the working directory) |
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

`fact-audit` always exits `0` and writes a report, including when Opengrep finds nothing.

## Tests

```bash
uv run python -m unittest discover -s tests
```

25 tests, no network required. One live-feed test is opt-in:

```powershell
$env:DEPSCAN_ONLINE_TEST="1"; uv run python -m unittest tests.test_deps.OnlineTest
```

## Limitations

- Dependency scanning is offline by default and supports only public feeds; private registries are out of scope.
- Python transitive dependencies are not resolved in this version.
- `go.sum` is best-effort and may list historical module versions; no Go toolchain is invoked.
- Vendored code (`vendor/`, `third_party/`) is skipped and only noted in the summary.
- The code-audit report depends on the configured LLM endpoint and the `GROQ_API_KEY`.
