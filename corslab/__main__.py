"""Offline synthetic CLI: bounded inputs/outputs, fresh report files only."""

import argparse
import html
import json
import sys
from pathlib import Path

from .contracts import INPUT_BYTES, OUTPUT_BYTES, Invalid, parse
from .model import evaluate


def markdown(report):
    def cell(value):
        # Report cells are untrusted content. Escape raw HTML and Markdown
        # formatting/link/image syntax before opening the artifact in a viewer.
        value = html.escape(str(value), quote=True).replace("\n", " ").replace("\r", " ")
        for char in "\\|`*_{}[]()!#":
            value = value.replace(char, "\\" + char)
        return value
    columns = ["id", "supported", "preflight_required", "preflight_passed", "actual_request_sent",
               "response_exposed", "intended_origin_allowed", "fixture_effect"]
    lines = ["# Restricted offline CORS model", "", "No browser/network/server testing performed.", "",
             "| " + " | ".join(columns) + " |", "| " + " | ".join("---" for _ in columns) + " |"]
    for row in report["results"]:
        lines.append("| " + " | ".join(cell(row[key]) for key in columns) + " |")
    lines.extend(["", "Unsupported values are unknown, not denials. Fixture effects are memory-only."])
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline CORS/preflight policy reasoning; no network.")
    parser.add_argument("input", nargs="?", default=str(Path(__file__).resolve().parent.parent / "fixtures/cases.json"))
    parser.add_argument("--output", help="Fresh file, never overwrites")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    args = parser.parse_args(argv)
    try:
        with Path(args.input).open("rb") as source:
            raw = source.read(INPUT_BYTES + 1)
        report = evaluate(parse(raw))
        payload = (json.dumps(report, ensure_ascii=True, indent=2) + "\n"
                   if args.format == "json" else markdown(report))
        encoded = payload.encode("utf-8")
        if len(encoded) > OUTPUT_BYTES:
            raise Invalid("OUTPUT_LIMIT")
        if args.output:
            # Exclusive creation rejects existing files, including input aliases.
            # Prepare/validate everything before creation; a rare local write error
            # may leave a partial fresh file, which is reported as failure.
            with Path(args.output).open("xb") as destination:
                destination.write(encoded)
            print(json.dumps({"report": args.output, "case_count": report["case_count"],
                              "simulation_kind": report["simulation_kind"]}))
        else:
            print(payload, end="")
        return 2 if report["unsupported_count"] else 0
    except (Invalid, OSError, UnicodeError) as exc:
        print(json.dumps({"schema_version": 1, "status": "INVALID",
                          "reason": str(exc) if isinstance(exc, Invalid) else "LOCAL_IO_ERROR"}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
