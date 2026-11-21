import tempfile
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock

import flet as ft

from fact_audit.ui import main, run_scans


def write(root: Path, name: str, content: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


class RunScansTest(unittest.TestCase):
    def test_deps_only_writes_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "requirements.txt", "requests==2.31.0\n")
            lines: list[str] = []

            written = run_scans(root, semgrep=False, deps=True, log=lines.append)

            self.assertEqual([p.name for p in written], ["deps-report.md"])
            report = (root / "deps-report.md").read_text(encoding="utf-8")
            self.assertIn("| requests | 2.31.0 | python", report)
            self.assertIn("Scanning dependencies...", lines)
            self.assertTrue(any("scanned: requirements.txt" in line for line in lines))

    def test_failing_stage_does_not_stop_deps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "requirements.txt", "requests==2.31.0\n")
            lines: list[str] = []

            with mock.patch("fact_audit.ui.run_audit", side_effect=RuntimeError("no key")):
                written = run_scans(root, semgrep=True, deps=True, log=lines.append)

            self.assertEqual([p.name for p in written], ["deps-report.md"])
            self.assertTrue(any("failed: no key" in line for line in lines))

    def test_missing_folder_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                run_scans(Path(tmp) / "missing", semgrep=False, deps=True, log=lambda _: None)

    def test_nothing_selected_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            written = run_scans(Path(tmp), semgrep=False, deps=False, log=lambda _: None)
            self.assertEqual(written, [])

    def test_main_builds_page(self):
        page = MagicMock()
        main(page)
        page.add.assert_called_once()
        root = page.add.call_args.args[0]
        self.assertIsInstance(root, ft.Column)
        self.assertEqual(len(root.controls), 5)


if __name__ == "__main__":
    unittest.main()
