import subprocess

class GitError(RuntimeError):
    """Git could not report changes; this must not look like 'no changes'."""

def get_changed_files(project_path: str, baseline: str = "HEAD") -> list[str]:
    try:
        result = subprocess.run(
            ["git", "-C", project_path, "diff", "--name-only", "--diff-filter=d", baseline],
            capture_output=True, text=True, encoding="utf-8", errors="replace", check=True
        )
    except FileNotFoundError as exc:
        raise GitError("git is not installed or not on PATH") from exc
    except subprocess.CalledProcessError as exc:
        raise GitError(f"git diff against '{baseline}' failed: {exc.stderr.strip()}") from exc
    return [f for f in result.stdout.strip().split("\n") if f]
