import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fact_audit.engines.opengrep import _binary, run_opengrep


class BinaryTest(unittest.TestCase):
    def test_prefers_installed_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            exe = (
                Path(tmp)
                / ".opengrep"
                / "cli"
                / "latest"
                / ("opengrep.exe" if os.name == "nt" else "opengrep")
            )
            exe.parent.mkdir(parents=True)
            exe.touch()
            with mock.patch("fact_audit.engines.opengrep.Path.home", return_value=Path(tmp)):
                self.assertEqual(_binary(), str(exe))

    def test_falls_back_to_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("fact_audit.engines.opengrep.Path.home", return_value=Path(tmp)):
                self.assertEqual(_binary(), "opengrep")

    def test_decodes_output_as_utf8(self):
        with mock.patch("fact_audit.engines.opengrep.subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout=json.dumps({"results": []}), stderr="")
            run_opengrep("proj")
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["encoding"], "utf-8")
        self.assertEqual(kwargs["errors"], "replace")
