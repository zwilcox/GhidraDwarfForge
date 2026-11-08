#!/usr/bin/env python3
"""Pure transcript controls: no Ghidra, producer, debugger or artifact writes."""
import copy
import json
from pathlib import Path
import runpy
import unittest


parse = runpy.run_path(str(Path(__file__).with_name("call-site-packaged.py")))["headless_reports"]


def report_line(report):
    return "INFO  GhidraDwarfForge.java> GhidraDwarfForge report: " + json.dumps(report) + " (GhidraScript)  \n"


class TranscriptTests(unittest.TestCase):
    def setUp(self):
        self.report = {"schemaVersion": 2, "status": "PARTIAL", "failure": None,
                       "failedFunctions": [], "diagnostics": ["Skipped thunk function fixture"]}
        self.omission = "ERROR GhidraDwarfForge.java> GhidraDwarfForge: Skipped thunk function fixture (GhidraScript)  \n"
        self.one = self.omission + report_line(self.report)

    def test_accounted_omissions(self):
        self.assertEqual(parse(self.one * 2), [self.report, self.report])

    def test_success_without_omissions(self):
        self.report.update(status="SUCCESS", diagnostics=[])
        self.assertEqual(len(parse(report_line(self.report) * 2)), 2)

    def test_terminal_or_invalid_reports(self):
        mutations = ({"status": "FATAL"}, {"status": "CANCELLED"},
                     {"failure": {"message": "failed"}}, {"schemaVersion": 1},
                     {"diagnostics": []}, {"diagnostics": "Skipped thunk function fixture"},
                     {"failedFunctions": [{"name": "cs_leaf"}]})
        for change in mutations:
            with self.subTest(change=change):
                altered = copy.deepcopy(self.report)
                altered.update(change)
                with self.assertRaises(AssertionError):
                    parse(self.one + self.omission + report_line(altered))

    def test_unexpected_errors_even_after_success(self):
        errors = ("ERROR HeadlessAnalyzer: script failed\n",
                  "ERROR GhidraDwarfForge.java> GhidraDwarfForge report: {} (GhidraScript)\n",
                  "ERROR AnotherScript.java> GhidraDwarfForge: Skipped thunk function fixture (GhidraScript)\n",
                  "  ERROR hidden by indentation\n", "Traceback (most recent call last):\n",
                  self.omission)
        for error in errors:
            with self.subTest(error=error):
                with self.assertRaises(AssertionError):
                    parse(self.one * 2 + error)

    def test_each_export_accounts_for_its_own_diagnostics(self):
        altered = copy.deepcopy(self.report)
        altered["diagnostics"] = []
        with self.assertRaises(AssertionError):
            parse(self.one + self.omission + report_line(altered))

    def test_missing_extra_and_malformed_reports(self):
        for text in ("", self.one, self.one * 3,
                     self.one + "INFO  GhidraDwarfForge.java> GhidraDwarfForge report: broken\n",
                     self.one + report_line(self.report).replace("(GhidraScript)", "unexpected")):
            with self.subTest(text=text[:100]):
                with self.assertRaises((AssertionError, ValueError)):
                    parse(text)


if __name__ == "__main__":
    unittest.main()
