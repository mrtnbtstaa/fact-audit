import subprocess

def get_changed_files(project_path: str, baseline: str = "HEAD") -> list[str]:
    try:
        result = subprocess.run(
            ["git", "-C", project_path, "diff", "--name-only", "--diff-filter=d", baseline],
            capture_output=True, text=True, encoding="utf-8", errors="replace", check=True
        )
        return [f for f in result.stdout.strip().split("\n") if f]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []