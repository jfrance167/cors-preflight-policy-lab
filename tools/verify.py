"""Repeat local checks and two focused mutations; never installs or uses network.

Usage: python tools/verify.py FRESH_DIRECTORY
Outputs: full logs, exact commands/statuses, fixture/source hashes and results.json.
Requires existing Python and Bandit. Fixed mutations restore exact bytes in finally.
"""

import hashlib
import json
from pathlib import Path
# Fixed owned-project verification commands only, never model/fixture text.
import subprocess  # nosec B404
import sys

ROOT = Path(__file__).resolve().parent.parent


def check(command, destination):
    with destination.open("x", encoding="utf-8") as output:
        try:
            completed = subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT,
                                       timeout=30, check=False)  # nosec B603
            return completed.returncode
        except subprocess.TimeoutExpired:
            return 124


def main():
    folder = Path(sys.argv[1]).resolve()
    folder.mkdir(parents=True, exist_ok=False)
    tests = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]
    commands = {"tests": tests, "optimized_tests": [sys.executable, "-O", *tests[1:]],
                "compile": [sys.executable, "-m", "compileall", "-q", "corslab", "tools", "tests"],
                "bandit": [sys.executable, "-m", "bandit", "-r", "corslab", "tools", "-f", "json"],
                "json_demo": [sys.executable, "-m", "corslab", "--output", str(folder / "demo.json")],
                "markdown_demo": [sys.executable, "-m", "corslab", "--format", "markdown", "--output", str(folder / "demo.md")]}
    checks = {name: {"command": command, "exit": check(command, folder / (name + ".log"))}
              for name, command in commands.items()}
    target = ROOT / "corslab/model.py"
    original = target.read_bytes()
    mutations = {
        "substring_origin": (b"if allowed != request_origin:", b"if allowed is None or allowed not in request_origin:"),
        "credentialed_wildcard": (b'if credentials != "include" and allowed == "*":', b'if allowed == "*":'),
    }
    for name, (search, replacement) in mutations.items():
        if original.count(search) != 1:
            raise RuntimeError("Expected exactly one mutation location: " + name)
        try:
            target.write_bytes(original.replace(search, replacement))
            status = check(tests, folder / (name + ".log"))
        finally:
            target.write_bytes(original)
        checks[name] = {"exit": status, "detected": status == 1,
                        "restored": target.read_bytes() == original}
    checks["restored_tests"] = {"command": tests, "exit": check(tests, folder / "restored-tests.log")}
    manifest = {str(path.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(path.read_bytes()).hexdigest()
                for parent in ("corslab", "tests", "tools", "fixtures")
                for path in sorted((ROOT / parent).glob("*")) if path.is_file()}
    passed = (all(checks[name]["exit"] == (2 if name.endswith("demo") else 0) for name in commands)
              and checks["restored_tests"]["exit"] == 0
              and all(checks[name]["detected"] and checks[name]["restored"] for name in mutations))
    report = {"status": "PASS" if passed else "FAIL", "checks": checks, "sha256": manifest}
    (folder / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "evidence": str(folder)}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
