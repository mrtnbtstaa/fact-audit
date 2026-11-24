import json
import os
import subprocess
from pathlib import Path

from fact_audit.dataclasses.fidings import Finding
from fact_audit.findings import normalize


def _strings(value) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


class EngineError(RuntimeError):
    """The static analysis engine could not run or return usable output."""


def _binary() -> str:
    """Use the installer's location; PATH is stale in long-running shells and Explorer."""
    installed = Path.home() / ".opengrep" / "cli" / "latest" / (
        "opengrep.exe" if os.name == "nt" else "opengrep"
    )
    return str(installed) if installed.is_file() else "opengrep"


def run_opengrep(
    project_path: str, target_files: list[str] = None, sarif_path: str = None
) -> list[Finding]:
    print(f"Running opengrep on: {project_path}...")
    
    # Determine what to scan: specific files (if diff mode) or the whole project
    targets = target_files if target_files else [project_path]
    
    # Build the command dynamically
    cmd = [_binary(), "--config=auto", "--json", "--quiet"]
    if sarif_path:
        cmd += ["--sarif-output", str(sarif_path)]
    cmd.extend(targets)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600
        )
    except FileNotFoundError as exc:
        raise EngineError(
            "the 'opengrep' command was not found; install it or add it to your PATH"
        ) from exc

    # 1. Check if Opengrep crashed
    if result.returncode != 0:
        raise EngineError(
            f"opengrep exited with code {result.returncode}: {result.stderr.strip()}"
        )

    # 2. Look at what Opengrep actually returned
    raw_output = result.stdout
    if not raw_output.strip():
        raise EngineError(f"opengrep returned no output: {result.stderr.strip()}")

    # 3. Try to parse the JSON safely
    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError as e:
        raise EngineError(f"could not parse opengrep output: {e}") from e

    # 4. Print how many findings Opengrep actually found
    results = data.get("results", [])
    print(f"Opengrep raw results count: {len(results)}")

    findings = []
    for r in results:
        extra = r.get("extra", {})
        metadata = extra.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {}

        # Clean up the file path to make the report readable (remove the absolute project path)
        file_path = r.get("path", "")
        if target_files is None and file_path.startswith(project_path):
            file_path = file_path[len(project_path):].lstrip("\\/")

        confidence = str(metadata.get("confidence") or "").upper()
        findings.append(Finding(
            source="opengrep",
            file=file_path, # Use the cleaned path
            line=r.get("start", {}).get("line", 0),
            severity=extra.get("severity", "INFO").upper(),
            message=extra.get("message", ""),
            rule_id=r.get("check_id", ""),
            confidence=confidence if confidence in ("HIGH", "MEDIUM", "LOW") else "UNKNOWN",
            cwe=[c for c in _strings(metadata.get("cwe")) if c.upper().startswith("CWE-")],
            owasp=_strings(metadata.get("owasp")),
        ))
    return normalize(project_path, findings)