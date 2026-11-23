import contextlib
import io
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
