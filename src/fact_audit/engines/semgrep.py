import json
import subprocess
from fact_audit.dataclasses.fidings import Finding

def run_semgrep(project_path: str, target_files: list[str] = None) -> list[Finding]:
    print(f"Running semgrep on: {project_path}...")
    
    # Determine what to scan: specific files (if diff mode) or the whole project
    targets = target_files if target_files else [project_path]
    
    # Build the command dynamically
    cmd = ["semgrep", "--config=auto", "--json", "--quiet"]
    cmd.extend(targets)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=600
        )
    except FileNotFoundError:
        print("ERROR: The 'semgrep' command was not found. Is it installed and on your PATH?")
        return []

    # 1. Check if Semgrep crashed
    if result.returncode != 0:
        print(f"ERROR: Semgrep exited with code {result.returncode}")
        print(f"STDERR: {result.stderr}")
        return []

    # 2. Look at what Semgrep actually returned
    raw_output = result.stdout.strip()
    if not raw_output:
        print("ERROR: Semgrep returned empty output.")
        print(f"STDERR: {result.stderr}")
        return []

    # 3. Try to parse the JSON safely
    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to parse Semgrep JSON output: {e}")
        print("RAW OUTPUT WAS:")
        print(raw_output[:500] + "..." if len(raw_output) > 500 else raw_output)
        return []

    # 4. Print how many findings Semgrep actually found
    results = data.get("results", [])
    print(f"Semgrep raw results count: {len(results)}")

    findings = []
    for r in results:
        extra = r.get("extra", {})
        
        # Clean up the file path to make the report readable (remove the absolute project path)
        file_path = r.get("path", "")
        if target_files is None and file_path.startswith(project_path):
            file_path = file_path[len(project_path):].lstrip("\\/")
            
        findings.append(Finding(
            source="semgrep",
            file=file_path, # Use the cleaned path
            line=r.get("start", {}).get("line", 0),
            severity=extra.get("severity", "INFO").upper(),
            message=extra.get("message", "").strip(),
            rule_id=r.get("check_id", ""),
        ))
    return findings