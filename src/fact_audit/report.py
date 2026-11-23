import os
import json
import sys

from openai import OpenAI
from .engines.opengrep import Finding
from .normalize import SEVERITY_ORDER
from dotenv import load_dotenv

load_dotenv()

PROMPT = """You are a code audit report writer.
Below is a JSON list of findings from a static analysis engine.

RULES:
1. Only report issues that appear in the JSON below.
2. Do NOT add, infer, or speculate about any issue not listed.
3. If the list is empty, write exactly: "No issues detected."
4. Structure your report exactly like this:

# Code Audit Report

## Summary
- Total Findings: [count]
- Severity Breakdown: [X] High, [Y] Medium, [Z] Low
- Top Priorities: [List the top 2-3 most critical issues in one sentence each]
- Affected Files: [List the unique files that have High severity issues]

## Findings

### High Severity (or ERROR)
- **`file/path.py:line`** | Rule: `rule_id`
  - **Issue:** [message]
  - **Fix:** [one-sentence fix suggestion]

### Medium Severity (or WARNING)
- **`file/path.py:line`** | Rule: `rule_id`
  - **Issue:** [message]
  - **Fix:** [one-sentence fix suggestion]

### Low Severity (or INFO)
- **`file/path.py:line`** | Rule: `rule_id`
  - **Issue:** [message]
  - **Fix:** [one-sentence fix suggestion]

(Only include the severity sections that actually have findings in the JSON.)

FINDINGS JSON:
{facts}
"""

def render_findings(findings: list[Finding]) -> str:
    """Deterministic report, used when the LLM is disabled or unavailable."""
    if not findings:
        return "# Code Audit Report\n\nNo issues detected.\n"

    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    lines = [
        "# Code Audit Report",
        "",
        "## Summary",
        "",
        f"- Total Findings: {len(findings)}",
        "- Severity Breakdown: "
        + ", ".join(
            f"{counts[s]} {s}"
            for s in sorted(counts, key=lambda s: SEVERITY_ORDER.get(s, 99))
        ),
        "",
        "## Findings",
        "",
    ]
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.severity, []).append(finding)
    for severity in sorted(grouped, key=lambda s: SEVERITY_ORDER.get(s, 99)):
        lines += [f"### {severity}", ""]
        for finding in sorted(grouped[severity], key=lambda f: (f.file, f.line)):
            lines += [
                f"- **`{finding.file}:{finding.line}`** | Rule: `{finding.rule_id}`",
                f"  - {finding.message}",
            ]
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def generate_report(findings: list[Finding], use_llm: bool = True) -> str:
    if not use_llm:
        return render_findings(findings)

    key = os.environ.get("GROQ_API_KEY")
    if not key:
        print("warning: GROQ_API_KEY not set; writing deterministic report.", file=sys.stderr)
        return render_findings(findings)

    facts = [f.__dict__ for f in findings]
    try:
        client = OpenAI(
            base_url="https://api.groq.com/openai/v1",
            api_key=key,
        )
        resp = client.chat.completions.create(
            model="openai/gpt-oss-120b",
            messages=[{"role": "user", "content": PROMPT.format(facts=json.dumps(facts, indent=2))}],
            temperature=0.1,
        )
        return resp.choices[0].message.content
    except Exception as exc:
        print(
            f"warning: LLM report unavailable ({exc}); writing deterministic report.",
            file=sys.stderr,
        )
        return render_findings(findings)