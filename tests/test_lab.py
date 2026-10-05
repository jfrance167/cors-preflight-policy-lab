"""Source-reasoned frozen expectations and independent boundary/CLI checks."""

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from corslab.__main__ import main, markdown
from corslab.contracts import Invalid, Unsupported, headers, origin, parse
from corslab.model import evaluate

ROOT = Path(__file__).resolve().parent.parent
CASE_HASH = "bc314f0ddd7c20a5495dc05a464893a7470b7049e6fc35454952b4b731952e07"
EXPECTED_HASH = "b20a3699dd03fef8f773bc60662616e53dabb980a2548a5c521f3ac7cb24d430"


def document():
    return parse((ROOT / "fixtures/cases.json").read_bytes())


def one(**changes):
    data = document()
    data["cases"] = [{**data["cases"][0], **changes}]
    return data


class ScenarioTests(unittest.TestCase):
    def test_frozen_expected_results(self):
        for filename, digest in (("cases.json", CASE_HASH), ("expected.json", EXPECTED_HASH)):
            self.assertEqual(hashlib.sha256((ROOT / "fixtures" / filename).read_bytes()).hexdigest(), digest)
        expected = json.loads((ROOT / "fixtures/expected.json").read_text(encoding="utf-8"))["cases"]
        report = evaluate(document())
        self.assertEqual(report["case_count"], 32)
        self.assertEqual(report["unsupported_count"], 2)
        self.assertEqual({row["id"] for row in report["results"]}, set(expected))
        for row in report["results"]:
            with self.subTest(case=row["id"]):
                for key, value in expected[row["id"]].items():
                    if key != "rationale":
                        self.assertEqual(row[key], value, key)

    def test_private_intent_does_not_rewrite_browser_rules(self):
        data = one(origin="https://attacker.test", response={"status": 200, "headers": [["Access-Control-Allow-Origin", "https://attacker.test"]]})
        row = evaluate(data)["results"][0]
        self.assertTrue(row["response_exposed"])
        self.assertFalse(row["intended_origin_allowed"])

    def test_exact_origin_not_substring(self):
        row = evaluate(one(origin="https://trusted.test.attacker.test"))["results"][0]
        self.assertFalse(row["response_exposed"])
        self.assertFalse(row["intended_origin_allowed"])

    def test_credentialed_wildcard_never_exposes(self):
        row = evaluate(one(credentials="include", response={"status": 200, "headers": [["Access-Control-Allow-Origin", "*"], ["Access-Control-Allow-Credentials", "true"]]}))["results"][0]
        self.assertTrue(row["actual_request_sent"])
        self.assertFalse(row["response_exposed"])

    def test_missing_preflight_stops_transmission(self):
        row = evaluate(one(method="DELETE", effect_if_sent=True))["results"][0]
        self.assertTrue(row["preflight_required"])
        self.assertFalse(row["actual_request_sent"])
        self.assertFalse(row["fixture_effect"])

    def test_same_origin_credentials_mode_on_cross_origin_model(self):
        row = evaluate(one(credentials="same-origin", response={"status": 500, "headers": [["Access-Control-Allow-Origin", "*"]]}))["results"][0]
        self.assertTrue(row["response_exposed"])

    def test_unknown_headers_and_origins_are_unknown_not_denied(self):
        for changes in ({"headers": [["Range", "bytes=0-1"]]}, {"origin": "https://[::1]"},
                        {"headers": [["Content-Type", "text/plain;charset=utf-8"]]}, {"method": "PATCH"}):
            with self.subTest(changes=changes):
                row = evaluate(one(**changes))["results"][0]
                self.assertFalse(row["supported"])
                self.assertIsNone(row["actual_request_sent"])
                self.assertIsNone(row["response_exposed"])

    def test_method_case_sensitive_header_case_insensitive(self):
        for method_token, header_token, success in (("PUT", "X-TEST", True), ("put", "x-test", False)):
            pf = {"status": 200, "headers": [["Access-Control-Allow-Origin", "https://trusted.test"], ["Access-Control-Allow-Methods", method_token], ["Access-Control-Allow-Headers", header_token]]}
            row = evaluate(one(method="PUT", headers=[["X-Test", "demo"]], preflight=pf))["results"][0]
            self.assertEqual(row["actual_request_sent"], success)

    def test_extra_preflight_is_explicit_unsupported(self):
        row = evaluate(one(preflight={"status": 204, "headers": []}))["results"][0]
        self.assertFalse(row["supported"])
        self.assertIsNone(row["fixture_effect"])


class ContractTests(unittest.TestCase):
    def test_json_hard_bounds_duplicates_numerics(self):
        invalid = [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1.0}', b'{"x":1234567}',
                   b"[" * 9 + b"0" + b"]" * 9, b" " * 131073, b"\xff", b"{invalid}"]
        for raw in invalid:
            with self.subTest(raw=raw[:40]), self.assertRaises(Invalid):
                parse(raw)
        self.assertEqual(parse(b'{"x":"[[[[[[[[[["}')["x"], "[" * 10)

    def test_schema_type_and_untrusted_labels_rejected(self):
        for changes in ({"method": True}, {"effect_if_sent": 1}, {"expected": True},
                        {"id": ""}, {"credentials": "yes"}, {"origin": "https://trusted.test\r\n"}):
            with self.subTest(changes=changes), self.assertRaises(Invalid):
                evaluate(one(**changes))
        data = one()
        data["schema_version"] = True
        with self.assertRaises(Invalid):
            evaluate(data)

    def test_canonical_origin_labels_ports_and_numeric_hosts(self):
        for value in ("https://trusted.test/", "https://user@trusted.test", "https://trusted.test?x=1",
                      "https://Trusted.test", "https://trusted..test", "https://-bad.test",
                      "https://trusted.test.", "https://trusted.test:443", "http://trusted.test:80",
                      "https://trusted.test:0443", "https://trusted.test:65536", "https://trusted.test:0"):
            with self.subTest(value=value), self.assertRaises(Invalid):
                origin(value)
        for value in ("https://127.0.0.1", "https://127.1", "https://0x7f.0x1", "https://[::1]", "https://é.test"):
            with self.subTest(value=value), self.assertRaises(Unsupported):
                origin(value)
        self.assertEqual(origin("https://good-name.test:8443"), "https://good-name.test:8443")

    def test_duplicate_case_insensitive_headers_and_combined_singletons(self):
        with self.assertRaises(Invalid):
            headers([["X-Test", "one"], ["x-test", "two"]])
        for fields in ([["ACcess-Control-Allow-Origin", "*"], ["access-control-allow-origin", "https://trusted.test"]],
                       [["Access-Control-Allow-Origin", "https://trusted.test, https://attacker.test"]],
                       [["Access-Control-Allow-Credentials", "true, true"]],
                       [["Access-Control-Allow-Headers", "x-test, X-Test"]],
                       [["Access-Control-Allow-Methods", "PUT,,DELETE"]]):
            with self.subTest(fields=fields), self.assertRaises(Invalid):
                evaluate(one(response={"status": 200, "headers": fields}))

    def test_full_document_rejected_if_later_case_invalid(self):
        data = document()
        data["cases"][-1]["response"]["status"] = True
        with self.assertRaises(Invalid):
            evaluate(data)
        data = document()
        data["cases"].append(copy.deepcopy(data["cases"][0]))
        with self.assertRaises(Invalid):
            evaluate(data)

    def test_limits_and_surrogates(self):
        for changes in ({"id": "x" * 65}, {"headers": [["x-test", "x" * 257]]},
                        {"headers": [["x-test", "\ud800"]]}, {"headers": [["x-test", "bad\x00"]]},
                        {"response": {"status": 600, "headers": []}}):
            with self.subTest(changes=changes), self.assertRaises(Invalid):
                evaluate(one(**changes))


class CLITests(unittest.TestCase):
    def invoke(self, *args):
        return subprocess.run([sys.executable, "-m", "corslab", *map(str, args)],
                              capture_output=True, text=True, cwd=ROOT, timeout=10)

    def test_cli_default_complete_json_and_markdown(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["case_count"], 32)
        report = self.invoke("--format", "markdown")
        self.assertEqual(report.returncode, 2)
        self.assertIn("trusted-403", report.stdout)
        self.assertIn("No browser/network/server testing", report.stdout)

    def test_fresh_file_and_input_alias_preserved(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as folder:
            source, target = Path(folder) / "source.json", Path(folder) / "report.json"
            source.write_text(json.dumps(one()), encoding="utf-8")
            original = source.read_bytes()
            self.assertEqual(self.invoke(source, "--output", target).returncode, 0)
            saved = target.read_bytes()
            self.assertEqual(self.invoke(source, "--output", target).returncode, 3)
            self.assertEqual(target.read_bytes(), saved)
            self.assertEqual(self.invoke(source, "--output", source).returncode, 3)
            self.assertEqual(source.read_bytes(), original)

    def test_invalid_cli_writes_no_report_or_traceback(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as folder:
            source, target = Path(folder) / "source.json", Path(folder) / "report.json"
            source.write_text('{"schema_version":1234567}', encoding="utf-8")
            result = self.invoke(source, "--output", target)
            self.assertEqual(result.returncode, 3)
            self.assertEqual(json.loads(result.stdout)["status"], "INVALID")
            self.assertEqual(result.stderr, "")
            self.assertFalse(target.exists())

    def test_markdown_escaping_and_output_bound(self):
        data = one(id="cell|break\\end")
        self.assertIn("cell\\|break\\\\end", markdown(evaluate(data)))
        import contextlib
        import io
        with tempfile.TemporaryDirectory(dir=ROOT) as folder:
            output = Path(folder) / "report.json"
            with patch("corslab.__main__.OUTPUT_BYTES", 10), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--output", str(output)]), 3)
            self.assertFalse(output.exists())

    def test_evaluation_never_opens_network(self):
        with patch("socket.socket", side_effect=AssertionError("network forbidden")), patch("subprocess.Popen", side_effect=AssertionError("child forbidden")):
            report = evaluate(document())
        self.assertEqual(report["case_count"], 32)

    def test_report_cells_cannot_inject_html_or_markdown_images(self):
        rendered = markdown(evaluate(one(id='<img src="x">![image](https://example.test)')))
        self.assertNotIn("<img", rendered)
        self.assertIn("&lt;img", rendered)
        self.assertNotIn("![image]", rendered)
        self.assertIn("\\!\\[image\\]", rendered)


if __name__ == "__main__":
    unittest.main()
