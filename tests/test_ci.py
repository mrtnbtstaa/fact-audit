import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fact_audit.dataclasses.deps import Advisory, Config, Dependency, Manifest, ScanResult
from fact_audit.dataclasses.fidings import Finding
from fact_audit.engines.git_utils import GitError, get_changed_files
from fact_audit.engines.opengrep import EngineError
from fact_audit.main import run_ci_command
from fact_audit.findings import baseline_document, load_baseline, normalize, save_baseline
from fact_audit.report import generate_report, render_findings


def run_ci(argv: list[str]) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    code = 0
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            run_ci_command(argv)
        except SystemExit as exc:
            code = exc.code or 0
    return code, stdout.getvalue(), stderr.getvalue()


def scan_result(deps: list[Dependency] = None) -> ScanResult:
    return ScanResult(
        target=".",
        timestamp="2026-01-01T00:00:00",
        config=Config(),
        manifests=[
            Manifest(
                path="requirements.txt",
                kind="requirements",
                ecosystem="python",
                dependencies=deps or [],
            )
        ],
    )


def dependency(license: str = "MIT", severity: str = None) -> Dependency:
    advisories = (
        [Advisory(id="CVE-1", severity=severity, summary="s", url="https://x")]
        if severity
        else []
    )
    return Dependency(
        name="pkg",
        ecosystem="python",
        declared="1.0",
        version="1.0",
        license=license,
        advisories=advisories,
    )


def finding(severity: str) -> Finding:
    return Finding(
        source="opengrep", file="a.py", line=1, severity=severity, message="m", rule_id="r.x"
    )


class CiTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_pass_writes_artifacts(self):
        with mock.patch("fact_audit.main.run_audit", return_value=("# Code Audit Report\n", [])), \
             mock.patch("fact_audit.main.scan", return_value=scan_result()):
            code, out, _ = run_ci([str(self.root), "--out-dir", str(self.root / "artifacts")])

        self.assertEqual(code, 0)
        self.assertIn("PASS", out)
        self.assertTrue((self.root / "artifacts" / "report.md").is_file())
        self.assertTrue((self.root / "artifacts" / "deps-report.md").is_file())

    def test_error_finding_fails(self):
        with mock.patch("fact_audit.main.run_audit", return_value=("r", [finding("ERROR")])), \
             mock.patch("fact_audit.main.scan", return_value=scan_result()):
            code, out, _ = run_ci([str(self.root)])

        self.assertEqual(code, 1)
        self.assertIn("FAIL", out)

    def test_warning_passes_by_default_and_fails_when_asked(self):
        with mock.patch("fact_audit.main.run_audit", return_value=("r", [finding("WARNING")])), \
             mock.patch("fact_audit.main.scan", return_value=scan_result()):
            self.assertEqual(run_ci([str(self.root)])[0], 0)
            self.assertEqual(run_ci([str(self.root), "--fail-on", "warning"])[0], 1)

    def test_offline_does_not_gate_vulnerabilities(self):
        with mock.patch("fact_audit.main.run_audit", return_value=("r", [])), \
             mock.patch("fact_audit.main.scan", return_value=scan_result([dependency(severity="CRITICAL")])):
            code, out, _ = run_ci([str(self.root)])

        self.assertEqual(code, 0)
        self.assertIn("not checked (offline)", out)

    def test_online_critical_vulnerability_fails(self):
        with mock.patch("fact_audit.main.run_audit", return_value=("r", [])), \
             mock.patch("fact_audit.main.scan", return_value=scan_result([dependency(severity="CRITICAL")])), \
             mock.patch("fact_audit.engines.feeds.enrich"):
            code, out, _ = run_ci([str(self.root), "--online"])

        self.assertEqual(code, 1)
        self.assertIn("vulnerability", out)

    def test_license_gate_is_opt_in(self):
        deps = [dependency(license="GPL-3.0")]
        with mock.patch("fact_audit.main.run_audit", return_value=("r", [])), \
             mock.patch("fact_audit.main.scan", return_value=scan_result(deps)), \
             mock.patch("fact_audit.engines.feeds.enrich"):
            self.assertEqual(run_ci([str(self.root), "--online"])[0], 0)
            self.assertEqual(run_ci([str(self.root), "--online", "--fail-on-license"])[0], 1)

    def test_engine_failure_exits_three(self):
        with mock.patch("fact_audit.main.run_audit", side_effect=EngineError("missing")), \
             mock.patch("fact_audit.main.scan", return_value=scan_result()):
            code, out, err = run_ci([str(self.root)])

        self.assertEqual(code, 3)
        self.assertIn("FAIL", out)
        self.assertIn("missing", err)

    def test_bad_path_exits_two(self):
        code, _, err = run_ci([str(self.root / "missing")])
        self.assertEqual(code, 2)
        self.assertIn("not a directory", err)

    def test_no_llm_and_sarif_are_passed_through(self):
        with mock.patch("fact_audit.main.run_audit", return_value=("r", [])) as audit, \
             mock.patch("fact_audit.main.scan", return_value=scan_result()):
            run_ci([str(self.root), "--no-llm", "--diff"])

        args = audit.call_args.args
        self.assertEqual(args[2], "HEAD")
        self.assertFalse(args[3])
        self.assertTrue(str(args[4]).endswith("fact-audit.sarif"))


class BaselineGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.path = self.root / "fact-audit-baseline.json"

    def tearDown(self):
        self.tmp.cleanup()

    def finding(self, message: str, severity: str = "ERROR") -> Finding:
        item = Finding(
            source="opengrep", file="a.py", line=1, severity=severity, message=message, rule_id="r.x"
        )
        return normalize(str(self.root), [item])[0]

    def write_baseline(self, *findings: Finding) -> None:
        save_baseline(self.path, baseline_document(str(self.root), list(findings)))

    def run_with(self, findings: list[Finding], *extra: str) -> tuple[int, str, str]:
        with mock.patch("fact_audit.main.run_audit", return_value=("r", findings)), \
             mock.patch("fact_audit.main.scan", return_value=scan_result()):
            return run_ci(
                [str(self.root), "--baseline-file", str(self.path), "--out-dir", str(self.root), *extra]
            )

    def test_only_new_findings_are_gated(self):
        known = self.finding("known")
        self.write_baseline(known)

        code, out, _ = self.run_with([known])
        self.assertEqual(code, 0)

        code, out, _ = self.run_with([known, self.finding("added")])
        self.assertEqual(code, 1)
        self.assertIn("1 new/reintroduced code finding", out)

    def test_fail_on_all_gates_existing_findings(self):
        known = self.finding("known")
        self.write_baseline(known)

        self.assertEqual(self.run_with([known])[0], 0)
        self.assertEqual(self.run_with([known], "--fail-on-all")[0], 1)

    def test_max_new_limits_new_findings(self):
        known = self.finding("known")
        self.write_baseline(known)
        current = [known, self.finding("a"), self.finding("b")]

        self.assertEqual(self.run_with(current, "--max-new", "2", "--fail-on", "none")[0], 0)
        self.assertEqual(self.run_with(current, "--max-new", "1", "--fail-on", "none")[0], 1)

    def test_update_baseline_records_resolved(self):
        known = self.finding("known")
        self.write_baseline(known)
        added = self.finding("added")

        code, _, _ = self.run_with([added], "--update-baseline")

        self.assertEqual(code, 1)
        doc = load_baseline(self.path, str(self.root))
        self.assertEqual([r["fingerprint"] for r in doc["findings"]], [added.fingerprint])
        self.assertEqual([r["fingerprint"] for r in doc["resolved"]], [known.fingerprint])

    def test_diff_scoped_update_never_resolves(self):
        known = self.finding("known")
        self.write_baseline(known)
        added = self.finding("added")

        self.run_with([added], "--diff", "--update-baseline")

        doc = load_baseline(self.path, str(self.root))
        self.assertEqual(
            {r["fingerprint"] for r in doc["findings"]}, {known.fingerprint, added.fingerprint}
        )
        self.assertEqual(doc["resolved"], [])
        self.assertEqual(
            json.loads((self.root / "fact-audit.json").read_text(encoding="utf-8"))["summary"]["resolved"], 0
        )

    def test_corrupt_baseline_exits_two(self):
        self.path.write_text("{not json", encoding="utf-8")
        code, _, err = run_ci([str(self.root), "--baseline-file", str(self.path)])
        self.assertEqual(code, 2)
        self.assertIn("cannot read baseline", err)

    def test_max_new_requires_a_baseline(self):
        code, _, err = run_ci([str(self.root), "--max-new", "1"])
        self.assertEqual(code, 2)
        self.assertIn("require --baseline-file", err)

    def test_json_and_csv_reports_carry_status(self):
        known = self.finding("known")
        self.write_baseline(known)
        self.run_with([known, self.finding("added")])

        document = json.loads((self.root / "fact-audit.json").read_text(encoding="utf-8"))
        self.assertEqual(document["gate"]["scope"], "new")
        self.assertEqual(document["summary"]["by_status"], {"existing": 1, "new": 1})
        self.assertEqual(document["scanners"]["opengrep"], "ok")
        csv = (self.root / "fact-audit.csv").read_text(encoding="utf-8")
        self.assertIn(",new,", csv)
        self.assertIn(",existing,", csv)


class GitUtilsTest(unittest.TestCase):
    def test_failed_diff_raises_instead_of_looking_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(GitError):
                get_changed_files(tmp)


class ReportFallbackTest(unittest.TestCase):
    def test_render_findings_is_deterministic(self):
        text = render_findings([finding("ERROR"), finding("WARNING")])
        self.assertIn("Total Findings: 2", text)
        self.assertIn("a.py:1", text)
        self.assertIn("r.x", text)

    def test_missing_key_writes_deterministic_report(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            text = generate_report([finding("ERROR")])
        self.assertIn("a.py:1", text)

    def test_no_llm_never_calls_the_api(self):
        with mock.patch("fact_audit.report.OpenAI") as client:
            generate_report([finding("ERROR")], use_llm=False)
        client.assert_not_called()


if __name__ == "__main__":
    unittest.main()
