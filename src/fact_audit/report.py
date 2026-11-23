import os
import json

from openai import OpenAI
from .engines.opengrep import Finding
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

def generate_report(findings: list[Finding]) -> str:
    facts = [f.__dict__ for f in findings]
    client = OpenAI(
        base_url="https://api.groq.com/openai/v1",
        api_key=os.environ["GROQ_API_KEY"],
    )
    resp = client.chat.completions.create(
        model="openai/gpt-oss-120b",
        messages=[{"role": "user", "content": PROMPT.format(facts=json.dumps(facts, indent=2))}],
        temperature=0.1,
    )
    return resp.choices[0].message.content