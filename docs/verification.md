# Verification and ECC self-review — October5,2026

Evidence: [results.json](../reports/verification/results.json), full adjacent logs,
source/fixture SHA-256 hashes and JSON/Markdown demos. Python3.13.7 Windows only.

| Phase | Actual outcome |
|---|---|
| Unit/CLI checks | PASS: 21 tests, exit0; all32 frozen labels agree including2 unsupported |
| Optimized runtime | PASS: 21 tests under python -O, exit0 |
| Compile | PASS: compileall, exit0 |
| Bandit | PASS: exit0, zero findings; two narrow fixed-command B404/B603 suppressions in tools/verify.py |
| Exact-origin mutation | PASS: weakening equality to substring causes3 assertions to fail; exit1 |
| Credentialed-wildcard mutation | PASS: removing restriction causes2 assertions to fail; exit1 |
| Source restoration | PASS: exact bytes restored after each mutation;21 tests pass again |
| JSON/Markdown routes | PASS: complete32-case artifacts, expected exit2 for2 unknown cases |
| Type checker/linter | NOT RUN: no configured checker installed specifically for this project |
| Package build | NOT APPLICABLE: source-run stdlib project |
| Browser/upstream tests | NOT RUN: outside initial scope; model agreement is not conformance |
| Hosted CI/CodeQL/dependency audit | NOT RUN: no remote repository/publication or new dependencies |

Commands and source hashes are recorded, not inferred from this prose. No arbitrary
coverage requirement or broad security suppression was introduced. Bandit does not verify
protocol correctness. Mutation results establish sensitivity to two specific regressions,
not a comprehensive mutation score. Test no-network monkeypatches support pure evaluator
review but do not establish an OS sandbox or browser behavior.

## ECC review

Implementing-agent self-review used installed ecc-code-review and pinned reviewer checklist,
with surrounding contracts/model/CLI/callers/tests and verification helper. This untracked
new project has no separate Git history; task source files were read directly and scoped
parent status/diffs checked. Existing projects/shared tools/parent Git were not edited.

One MEDIUM finding fixed: corslab/__main__.py:13 markdown renderer originally escaped
only bars/backslashes/newlines. A custom ID containing raw HTML or Markdown image/link
syntax could inject report content in a consuming Markdown viewer. The renderer now escapes
HTML plus Markdown syntax; test_report_cells_cannot_inject_html_or_markdown_images verifies
the actual output. No actual browser exploitation was performed. Full normal/optimized
suite, compile, Bandit and both mutations ran after this fix; no known outstanding finding.

| Severity | Findings | Final status |
|---|---|---|
| CRITICAL |0|pass|
| HIGH |0|pass|
| MEDIUM |1|fixed, regression checked|
| LOW |0|pass|

Verdict: APPROVE for the authorized offline local scope. Not independent review or
authorization to merge/publish/deploy. Owner manual boundary review remains.

Protocol review: actual versus preflight status separated; null serialization distinct
from missing ACAO; strict exact origins; include-mode wildcard restrictions and true
case sensitivity; Authorization explicit allowance; GET/POST with unsafe headers; all
unknowns labeled rather than counted as denials. Residual limits are in SECURITY.md/README.

Reproduce `python tools/verify.py reports/FRESH_DIRECTORY` with installed Bandit and no
concurrent source writer. Complete original failed mutation output is retained. No
failed generation was shipped or lost; research/local-test-raw* captures sandbox denial
and local-test-local* captures the completed rejected Ollama draft.
