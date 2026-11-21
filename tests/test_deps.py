import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from fact_audit.dataclasses.deps import Config
from fact_audit.engines.deps import scan
from fact_audit.report_deps import render

PACKAGE_JSON = """{
  "name": "fixture",
  "dependencies": {"lodash": "4.17.15"},
  "devDependencies": {"left-pad": "^1.3.0"}
}
"""

PACKAGE_LOCK = """{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "fixture"},
    "node_modules/lodash": {"version": "4.17.15", "license": "MIT"},
    "node_modules/left-pad": {"version": "1.3.0", "license": "MIT"},
    "node_modules/ms": {"version": "2.0.0", "license": "MIT"}
  }
}
"""


def write(root: Path, name: str, content: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def scan_and_render(root: Path, **overrides) -> tuple[object, str]:
    config = Config(**overrides)
    result = scan(str(root), config)
    if config.online:
        from fact_audit.engines.feeds import enrich

        enrich(result)
    return result, render(result)


def cli(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "fact_audit", "deps", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


class ScanTest(unittest.TestCase):
    def test_npm_manifest_and_lockfile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "package.json", PACKAGE_JSON)
            write(root, "package-lock.json", PACKAGE_LOCK)
            result, report = scan_and_render(root)

            self.assertEqual(len(result.manifests), 2)
            self.assertIn("- Total dependency declarations: 5", report)
            self.assertIn("- Unique dependencies: 3", report)
            self.assertIn("| lodash | 4.17.15 | npm", report)
            self.assertIn("| left-pad | 1.3.0 (range) | npm", report)
            self.assertIn("| ms | 2.0.0 | npm", report)
            self.assertIn("| MIT |", report)
            self.assertIn("No advisories matched.", report)

    def test_empty_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, report = scan_and_render(root)
            self.assertIn(f"No supported dependency manifests were found in `{root.resolve()}`", report)
            self.assertIn("`package.json`", report)

    def test_malformed_manifest_does_not_abort(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "package.json", '{"dependencies": {"lodash": ')
            write(root, "requirements.txt", "requests==2.31.0\n")
            _, report = scan_and_render(root)

            self.assertIn("### Parse failures", report)
            self.assertIn("line 1", report)
            self.assertIn("| requests | 2.31.0 | python", report)

    def test_monorepo_aggregates_ecosystems(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "web/package.json", '{"dependencies": {"lodash": "4.17.15"}}')
            write(root, "api/requirements.txt", "flask==3.0.0\n")
            write(root, "svc/go.mod", "module example.com/svc\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n)\n")
            _, report = scan_and_render(root)

            self.assertIn("- Manifests found: 3 (parsed 3, failed 0)", report)
            self.assertIn("- Unique dependencies: 3", report)
            self.assertIn("| github.com/gin-gonic/gin | 1.9.0 | go", report)

    def test_range_dependency_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "requirements.txt", "flask>=3.0\nrequests==2.31.0\n")
            _, report = scan_and_render(root)
            self.assertIn("| flask | >=3.0 (range) | python", report)
            self.assertIn("| requests | 2.31.0 | python", report)

    def test_utf8_bom_manifest_is_parsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_bytes(
                "requests==2.31.0\n".encode("utf-8-sig")
            )
            _, report = scan_and_render(root)
            self.assertIn("| requests | 2.31.0 | python", report)

    def test_behind_distance(self):
        from fact_audit.engines.feeds import behind

        self.assertEqual(behind("1.2.3", "1.2.3"), "current")
        self.assertEqual(behind("1.2.3", "1.2.4"), "patch")
        self.assertEqual(behind("1.2.3", "1.3.0"), "minor")
        self.assertEqual(behind("1.2.3", "2.0.0"), "major")
        self.assertEqual(behind(None, "2.0.0"), "unknown")
        self.assertEqual(behind("1.2.3", None), "unknown")

    def test_offline_note(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "requirements.txt", "requests==2.31.0\n")
            _, report = scan_and_render(root)
            self.assertIn("Run was **offline**", report)
            self.assertIn("Mode: offline", report)
            self.assertIn("| unknown | unknown |", report)  # latest + behind

    def test_licenses_denylist_and_custom_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root,
                "package-lock.json",
                '{"lockfileVersion": 3, "packages": {'
                '"node_modules/mit-pkg": {"version": "1.0.0", "license": "MIT"},'
                '"node_modules/gpl-pkg": {"version": "2.0.0", "license": "GPL-3.0"},'
                '"node_modules/mystery": {"version": "3.0.0"}}}',
            )
            _, default_report = scan_and_render(root)
            self.assertIn("**Denylisted licenses detected:**", default_report)
            self.assertIn("`gpl-pkg@2.0.0` — GPL-3.0", default_report)
            self.assertNotIn("`mit-pkg@1.0.0` — MIT", default_report)
            self.assertIn("- Dependencies with unknown license: 1", default_report)

            _, custom_report = scan_and_render(root, denylist=["MIT"])
            self.assertIn("`mit-pkg@1.0.0` — MIT", custom_report)
            self.assertNotIn("`gpl-pkg@2.0.0` — GPL-3.0", custom_report)

    def test_report_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "package.json", PACKAGE_JSON)
            write(root, "package-lock.json", PACKAGE_LOCK)
            write(root, "go.mod", "module x\nrequire example.com/a v1.0.0\n")
            _, first = scan_and_render(root)
            _, second = scan_and_render(root)
            strip = lambda text: [l for l in text.splitlines() if not l.startswith("Generated:")]
            self.assertEqual(strip(first), strip(second))

    def test_vendored_directory_is_noted_not_enumerated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "vendor/package.json", '{"dependencies": {"lodash": "1.0.0"}}')
            write(root, "requirements.txt", "requests==2.31.0\n")
            result, report = scan_and_render(root)
            self.assertEqual(len(result.manifests), 1)
            self.assertIn("Vendored code detected (`vendor`)", report)


class CliTest(unittest.TestCase):
    def test_writes_report_and_prints_path_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "requirements.txt", "requests==2.31.0\n")
            out = root / "out" / "deps-report.md"
            result = cli(str(root), "--out", str(out), cwd=root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), str(out))
            self.assertTrue(out.is_file())
            self.assertIn("scanned: requirements.txt", result.stderr)

    def test_empty_project_exits_nonzero_but_still_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "deps-report.md"
            result = cli(str(root), "--out", str(out), cwd=root)
            self.assertEqual(result.returncode, 1)
            self.assertTrue(out.is_file())

            allowed = cli(str(root), "--out", str(out), "--allow-empty", cwd=root)
            self.assertEqual(allowed.returncode, 0)

    def test_missing_path_exits_nonzero_without_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "deps-report.md"
            result = cli(str(root / "nope"), "--out", str(out), cwd=root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not a directory", result.stderr)
            self.assertFalse(out.exists())

    def test_existing_stage_outputs_are_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "requirements.txt", "requests==2.31.0\n")
            sarif = write(root, "semgrep.sarif", '{"version": "2.1.0"}')
            diff = write(root, "diff.txt", "src/app.py\n")
            result = cli(str(root), cwd=root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(sarif.read_text(encoding="utf-8"), '{"version": "2.1.0"}')
            self.assertEqual(diff.read_text(encoding="utf-8"), "src/app.py\n")
            self.assertTrue((root / "deps-report.md").is_file())

    def test_refuses_to_overwrite_foreign_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "requirements.txt", "requests==2.31.0\n")
            existing = write(root, "report.md", "# Code Audit Report\n\nkeep me\n")
            result = cli(str(root), "--out", str(existing), cwd=root)
            self.assertEqual(result.returncode, 1)
            self.assertIn("refusing to overwrite", result.stderr)
            self.assertIn("keep me", existing.read_text(encoding="utf-8"))

    def test_rerun_overwrites_previous_deps_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "requirements.txt", "requests==2.31.0\n")
            first = cli(str(root), cwd=root)
            second = cli(str(root), cwd=root)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)

    def test_config_file_and_extra_manifests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "deps/python.txt", "flask==3.0.0\n")
            write(root, ".depscan.yml", "extra_manifests:\n  '*.txt': python\nallow_empty: true\n")
            result = cli(str(root), cwd=root)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = (root / "deps-report.md").read_text(encoding="utf-8")
            self.assertIn("| flask | 3.0.0 | python", report)
            self.assertIn("`*.txt` → python", report)

    def test_invalid_config_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "requirements.txt", "requests==2.31.0\n")
            write(root, ".depscan.yml", "denylist: not-a-list\n")
            result = cli(str(root), cwd=root)
            self.assertEqual(result.returncode, 1)
            self.assertIn("denylist must be a list", result.stderr)


@unittest.skipUnless(
    os.environ.get("DEPSCAN_ONLINE_TEST"), "set DEPSCAN_ONLINE_TEST=1 to hit live feeds"
)
class OnlineTest(unittest.TestCase):
    def test_vulnerable_package_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "package.json", '{"dependencies": {"lodash": "4.17.15"}}')
            result, report = scan_and_render(root, online=True)
            deps = [d for m in result.manifests for d in m.dependencies]
            self.assertTrue(deps[0].advisories)
            self.assertTrue(deps[0].latest)
            self.assertIn("GHSA-", report)
            self.assertIn("| lodash | 4.17.15 |", report)
            severities = [a.severity for a in deps[0].advisories]
            self.assertNotIn("MODERATE", severities)


if __name__ == "__main__":
    unittest.main()
