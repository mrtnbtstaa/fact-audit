import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fact_audit.dataclasses.fidings import Finding
from fact_audit.findings import (
    BaselineError,
    baseline_document,
    compare,
    csv_text,
    fingerprint,
    load_baseline,
    normalize,
    record,
    save_baseline,
    updated_baseline,
)


def finding(message: str = "eval used", rule: str = "r.eval", line: int = 1, severity: str = "ERROR") -> Finding:
    return Finding(
        source="opengrep", file="app.py", line=line, severity=severity, message=message, rule_id=rule
    )


class NormalizeTest(unittest.TestCase):
    def test_maps_severity_and_keeps_scanner_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            item = normalize(tmp, [finding()])[0]

        self.assertEqual(item.severity, "HIGH")
        self.assertEqual(item.scanner_severity, "ERROR")
        self.assertEqual(item.file, "app.py")
        self.assertTrue(item.fingerprint)

    def test_unknown_scanner_severity_stays_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            item = normalize(tmp, [finding(severity="NOTE")])[0]
        self.assertEqual(item.severity, "UNKNOWN")

    def test_absolute_path_becomes_project_relative(self):
        with tempfile.TemporaryDirectory() as tmp:
            absolute = str(Path(tmp) / "src" / "app.py")
            item = normalize(tmp, [Finding("opengrep", absolute, 3, "WARNING", "m", "r")])[0]
        self.assertEqual(item.file, "src/app.py")


class FingerprintTest(unittest.TestCase):
    def test_line_movement_keeps_the_fingerprint(self):
        self.assertEqual(fingerprint(finding(line=1)), fingerprint(finding(line=99)))

    def test_message_and_rule_separate_findings(self):
        base = fingerprint(finding())
        self.assertNotEqual(base, fingerprint(finding(message="other")))
        self.assertNotEqual(base, fingerprint(finding(rule="r.other")))

    def test_whitespace_in_message_is_normalized(self):
        self.assertEqual(fingerprint(finding(message="a  b")), fingerprint(finding(message="a b")))


class BaselineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.path = self.root / "fact-audit-baseline.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_roundtrip(self):
        findings = normalize(str(self.root), [finding()])
        save_baseline(self.path, baseline_document(str(self.root), findings, "abc123"))

        doc = load_baseline(self.path, str(self.root))
        self.assertEqual(doc["version"], 1)
        self.assertEqual(doc["revision"], "abc123")
        self.assertEqual(len(doc["findings"]), 1)
        self.assertEqual(doc["findings"][0]["severity"], "HIGH")

    def test_missing_file_is_an_error(self):
        with self.assertRaises(BaselineError):
            load_baseline(self.root / "nope.json", str(self.root))

    def test_corrupt_and_foreign_files_are_rejected(self):
        self.path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(BaselineError):
            load_baseline(self.path, str(self.root))

        self.path.write_text(json.dumps({"format": "other"}), encoding="utf-8")
        with self.assertRaises(BaselineError):
            load_baseline(self.path, str(self.root))

    def test_incompatible_versions_are_rejected(self):
        findings = normalize(str(self.root), [finding()])
        doc = baseline_document(str(self.root), findings)
        doc["fingerprint_version"] = 99
        save_baseline(self.path, doc)
        with self.assertRaises(BaselineError):
            load_baseline(self.path, str(self.root))

    def test_baseline_from_another_repository_is_rejected(self):
        findings = normalize(str(self.root), [finding()])
        with mock.patch("fact_audit.findings.repository_id", return_value="git@a/repo"):
            save_baseline(self.path, baseline_document(str(self.root), findings))
        with mock.patch("fact_audit.findings.repository_id", return_value="git@b/repo"):
            with self.assertRaises(BaselineError):
                load_baseline(self.path, str(self.root))


class CompareTest(unittest.TestCase):
    def test_new_existing_and_resolved(self):
        root = str(Path(tempfile.gettempdir()))
        known, added = normalize(root, [finding(message="known")])[0], normalize(root, [finding(message="added")])[0]
        baseline = baseline_document(root, [known])

        result = compare([known, added], baseline)

        self.assertEqual(result.status[known.fingerprint], "existing")
        self.assertEqual(result.status[added.fingerprint], "new")
        self.assertEqual(result.resolved, [])

        result = compare([added], baseline)
        self.assertEqual(result.status[added.fingerprint], "new")
        self.assertEqual([r["fingerprint"] for r in result.resolved], [known.fingerprint])

    def test_resolved_finding_is_reintroduced_when_it_returns(self):
        root = str(Path(tempfile.gettempdir()))
        item = normalize(root, [finding()])[0]
        baseline = baseline_document(root, [], resolved=[{"fingerprint": item.fingerprint}])

        self.assertEqual(compare([item], baseline).status[item.fingerprint], "reintroduced")

    def test_updated_baseline_keeps_resolved_history(self):
        root = str(Path(tempfile.gettempdir()))
        old, new = normalize(root, [finding(message="old")])[0], normalize(root, [finding(message="new")])[0]
        baseline = baseline_document(root, [old])

        doc = updated_baseline(root, [new], baseline, "rev2")

        self.assertEqual([r["fingerprint"] for r in doc["findings"]], [new.fingerprint])
        self.assertEqual([r["fingerprint"] for r in doc["resolved"]], [old.fingerprint])


class ClassificationTest(unittest.TestCase):
    def test_cwe_and_owasp_reach_the_record_and_csv(self):
        item = Finding(
            source="opengrep",
            file="app.py",
            line=2,
            severity="ERROR",
            message="m",
            rule_id="r",
            cwe=["CWE-95: Eval Injection"],
            owasp=["A03:2021 - Injection"],
        )
        with tempfile.TemporaryDirectory() as tmp:
            item = normalize(tmp, [item])[0]

        self.assertEqual(record(item)["cwe"], ["CWE-95: Eval Injection"])
        self.assertEqual(record(item)["owasp"], ["A03:2021 - Injection"])
        self.assertIn("A03:2021 - Injection", csv_text([item], {}))


class CsvTest(unittest.TestCase):
    def test_formula_cells_are_prefixed(self):
        item = Finding(
            source="opengrep",
            file="=cmd.xls",
            line=1,
            severity="ERROR",
            message="=1+1",
            rule_id="r",
        )
        with tempfile.TemporaryDirectory() as tmp:
            item = normalize(tmp, [item])[0]

        row = csv_text([item], {}).splitlines()[1]
        self.assertIn("'=cmd.xls", row)
        self.assertIn("'=1+1", row)

    def test_header_and_row_per_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            items = normalize(tmp, [finding(), finding(message="other", line=7)])
        text = csv_text(items, {items[0].fingerprint: "new"})
        lines = text.strip().splitlines()

        self.assertEqual(
            lines[0],
            "fingerprint,status,severity,confidence,rule_id,cwe,owasp,file,line,message",
        )
        self.assertEqual(len(lines), 3)
        self.assertIn(",new,", lines[1])


if __name__ == "__main__":
    unittest.main()
