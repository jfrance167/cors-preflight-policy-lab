# Offline CORS and preflight policy lab — proposed plan

Prepared October 5, 2026. Research/planning only; no application code written.
Implementation approval subsequently received October5 01:06 Eastern for stages2–4.
Addendum read from coordinator SUCCESSORS.md before code: actual403/404 responses can
be readable; only preflight needs successful2xx status. Safelisted GET/POST triggered
by unsafe headers do not need explicit method allowance. Enforce Authorization's
non-wildcard rule, credentials-dependent wildcard methods/headers, duplicate
case-insensitive header and ambiguous value rejection, bounded numeric tokens/final
output, strict canonical origin labels/ports/numeric-host refusal, independent labels.
Maintain separate protocol/transmission/intent and explicit unsupported cases.
Recommendation: build a small original standard-library Python model, using primary
standards and selected WPT cases as references. Do not fork a web framework or run
third-party browser infrastructure for this initial scope.

## Authorization and purpose

Original human messages independently verified in chat
`01a10a45-1a24-78b3-9cef-7c461a966d26`: Jake authorized that chat to approve/start
work across his chats, then asked it to create more labs after completion. Turns
`01a10a45-2549-7333-8a33-edd64a1dd4fa` and
`01a10a4f-2230-7433-90e7-e2cff1fa15e9` are the original user evidence, not relayed
agent quotations. Coordinator assigned this bounded research comparison. Implementation
awaits coordinator review of this concrete plan. Dispatch cutoff: October 6, 08:00 Eastern.
No new chat, scheduler, publication, credentials or external testing authorized here.

Problem: learners often collapse server authorization, request transmission and browser
response visibility into a single allow/deny result. This lab must make those boundaries
visible separately while preserving legitimate public and explicitly trusted reads.

Success: a deterministic CLI evaluates reviewed fictional scenarios, records each modeled
stage, contrasts unsafe header policy with an exact allowlist policy, and explains why
an unreadable response does not prove the server avoided processing a request. All
results are labeled offline model evidence, with no browser/production claims.

## Reuse and distinct scope

Inspected `web-access-control-security-lab/access_control_lab.py`, its test suite,
README, and Obsidian `01 Projects/Web Authorization Lab.md`. That lab models identity,
role, ownership, endpoint and tenant decisions across eleven fictional scenarios.
It has no CORS/preflight model or graphify graph. Reuse its readable JSON/Markdown
reporting pattern and legitimate-control philosophy, without editing/copying its code
or rerunning its tests. It lacks STATE.md; this was a missing record, not a failed lab.

The completed prompt-injection firewall stays unchanged, including its owner review,
deferred API/real-model work, and recorded 10/80 scripted attack successes/30/40 benign
completion. This successor shares no inference or runtime dependency with it.

## Source-backed boundaries

- Response CORS checks compare serialized origins; credentials mode `include` cannot
  use an allow-origin wildcard and requires byte-sensitive `true` credentials support.
  Preflight acceptance additionally concerns status, method and requested headers.
  Preflight does not carry credentials. [Fetch CORS protocol/check](https://fetch.spec.whatwg.org/#cors-protocol)
- Tuple origins compare scheme, host and port. Opaque origins serialize as `null`,
  which cannot identify their underlying origin. [HTML origins](https://html.spec.whatwg.org/multipage/browsers.html#origin)
  and [URL origins](https://url.spec.whatwg.org/#origin).
- Form-like requests can be sent without preflight while response sharing still needs
  CORS approval. [MDN CORS guide](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS).
- CORS and CSRF configuration are separate controls. Authentication/authorization and
  CSRF protection remain server responsibilities. [Django middleware documentation](https://github.com/adamchainz/django-cors-headers/blob/main/README.rst)
  and [OWASP CSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).
- Authorization headers need explicit allowance rather than generic wildcard coverage
  in the inspected browser tests. [WPT preflight tests](https://github.com/web-platform-tests/wpt/blob/master/fetch/api/cors/cors-preflight.any.js).

Use two independent axes: protocol permits script exposure versus application's intended
origin policy permits sharing. Reflecting arbitrary origins with credentials can pass
protocol checks while violating application intent; literal wildcard plus credentials
fails protocol checks. Report both, never call either server authorization.

## Candidates and alternatives

| Candidate | Evidence inspected | Fit and decision |
|---|---|---|
| adamchainz/django-cors-headers | Middleware, tests, manifest, MIT license, changelog, CI source, credentials issues | Maintained source with sync/async tests, Python matrix and pinned CI actions. Runtime Django/asgiref are unnecessary here; reference behavior/tests, do not adopt runtime or call CI green without run evidence. |
| web-platform-tests/wpt | README, BSD-3-Clause license, preflight JS and Python helper, runner requirements, issues | Standards-linked cross-browser reference, unarchived. Running it brings browsers, HTTP harness and many dependencies. Reference selected cases only; CI definition retrieval failed and no tests were run. |
| Cookie-attribute model | MDN Set-Cookie reference and relevant vault cookie-boundary note | Useful later: Secure/HttpOnly/SameSite, host/domain/path and cookie prefixes. Cookie-store, site/public-suffix and browser-policy variations broaden correctness obligations; defer. |

Both source repositories are confirmed through the connected GitHub integration.
Research/file blob SHAs and failed retrievals are in `research/source-record.json`.
Issue996 illustrates confusion about broad reflection/credentials; inspected middleware
and tests resolve the actual emitted header behavior. WPT issue20517 reports a historical
test-return defect; it is a caution to read tests, not evidence that current CORS tests
are broken. Search returned no state/timestamps for those issues, so status is unverified.
Changelog/test/CI inspection supports maintenance assessment; stars were not used.
No dependency vulnerability scan or Scorecard assessment was performed; neither project
is certified safe. Searches were narrow, not exhaustive.

Adopt/fork/build decision: BUILD original restricted model. Retain source links and
AI-assistance disclosure. If implementation copies substantial upstream material,
include MIT copyright/permission or BSD-3-Clause attribution/disclaimer/no-endorsement
terms as applicable. Planned independent fixtures need source attribution, not copied
implementation. No package installation, framework or browser runner needed.

## Scope and architecture

CLI -> bounded schema/origin validation -> fixture policy header builder -> modeled
preflight/transmission/exposure stages -> intention comparison -> JSON/Markdown report.
Suggested modules: contracts, origins, policy, evaluator, reports, CLI; no plugin system.

Inputs are local synthetic JSON, at most 128 KiB/100 cases/depth8. Strict types, unique
case IDs, duplicate-key rejection, finite values, no silent coercion, bounded strings
(origin512 bytes/header value256 bytes), at most32 headers. Invalid data produces
structured error and nonzero exit; unsupported browser features produce explicit
UNSUPPORTED, never a conformance pass. Output is fresh, human-selected local file;
Markdown cells escape bars/newlines, JSON is data, no HTML rendering or template code.

Support only canonical serialized HTTP/HTTPS origins using lowercase ASCII DNS hosts,
ordinary numeric ports and the literal `null`. Reject paths, query/fragment, userinfo,
whitespace, CR/LF, host suffix tricks and multiple origin values. Require canonical
serialization; default ports are omitted. Origin URLs used for explanation are never
resolved or fetched. IPv6, IDNA/Unicode, unusual IP forms and non-HTTP schemes explicitly
unsupported initially; urllib parsing alone is not browser URL conformance.

Model cross-origin `mode=cors`, no redirect, empty preflight cache, explicit credentials
mode, GET/HEAD/POST/PUT/DELETE, and a documented header subset: canonical Content-Type
values text/plain, application/x-www-form-urlencoded, multipart/form-data without
parameters; application/json, Authorization and x-test require preflight. Other header
safelisting/value rules are unsupported rather than approximated. Credential availability
and server intent are fixture facts; never invent real cookie attachment.

Response fields separately record preflight_required, preflight_passed, actual_request_sent,
response_exposed, intended_origin_allowed, reason_codes and simulation_kind. Separate
preflight versus actual response header/status sets. Failed preflight stops modeled
actual transmission; a sent safelisted POST can still have an unreadable response.
An explicit fixture `server_effect_if_sent` illustrates that distinction in memory;
it does not predict a real server, authenticate users, or perform a write.

No service/network requests, browser execution, cookie store, production header editing,
credentials, live-site testing, cache simulation, redirects, service workers, private
network access, no-cors/navigation or full Fetch compliance. Public wildcard/no-credential
reads are legitimate controls. Conservative `null` refusal is application policy, not
a claim that the protocol can never share with serialized null.

## Threat model and tradeoffs

Assets: accurate explanations, safe local execution, preserved files and reproducible
evidence. Untrusted inputs: fixture text, origin/header strings, labels and report cells.
Attacker can request malformed inputs and misleading origins; cannot edit trusted policy
or expected labels inside the evaluator. No input can authorize network or shell use.

Risks: parser/browser divergence, conflating null with absent header, treating matching
host suffix as matching origin, collapsing transmission and visibility, and self-grading
fixtures. Mitigate with restricted canonical grammar, independent source-linked expected
results, explicit unsupported outcomes, separate fields and focused mutation checks.
This model's limitations are more consequential than adding framework dependencies.

## Stages and definitions of done

1. **Review gate (current):** coordinator accepts/revises this scope and records decision.
   No project code before that decision; state and research files are the handoff.
2. **One complete read scenario:** strict JSON/origin contracts, public and trusted-origin
   read controls through CLI to report; reject malformed origins/input and overwrite.
3. **Preflight and unsafe contrast:** transmission/exposure separation, explicit method/
   header/status checks, null/reflection/wildcard-credentials contrasts and fictional effect
   ledger. At least24 reviewed distinct cases, including legitimate and denied controls;
   freeze labels before evaluating, no automatic generated expectations.
4. **Verification and portfolio docs:** stdlib unit/CLI tests, compileall, installed Bandit,
   ECC actual-code self-review/fixes, JSON/Markdown inspection and mutation evidence.
   README/demo, threat model, limitations, license/attribution/disclosure, STATE/DECISIONS/
   LEARNING and verified Obsidian milestone. No GitHub remote/init/publication in this scope.

Stages2–4 stay within this proposed offline model. Full browser comparison is a separate
future decision, not quietly added to completion criteria.

## Verification strategy and learning

Independent cases: exact trusted origin; wrong scheme/port/subdomain/suffix; missing versus
serialized null; public wildcard omit succeeds; credentialed wildcard fails; exact origin
include needs `true` (not `True`); broad reflection exposes an unintended origin; allowed
and denied PUT/header preflights; Authorization explicit allowance; safelisted POST sent
but response unreadable; failing actual response after successful preflight; malformed/
oversized/control-character/duplicate JSON; report escaping and CLI errors.

Mutations should make tests fail when exact origin comparison becomes substring matching
or when the credentialed-wildcard restriction is removed. Restore original bytes and
rerun affected tests. Freeze expected labels separately from evaluator implementation.
Report modeled agreement and per-stage results, not vulnerability prevalence, browser
pass rates or production protection. Record checks not run as such.

Local Ollama bounded six-idea draft was attempted through the reviewed loopback helper:
first sandbox EACCES, then approved loopback attempt completed in1.346s but confused
server rejection with browser enforcement and replaced the POST boundary with method
rejection. Raw outputs preserved; draft rejected. Remote free capacity was considered
but not used to replace these security judgments; Codex verified the sources/plan.
No paid fallback, remote inference, retries after the completed weak draft or new service.

Optional learning check after implementation: explain why a modeled POST effect can occur
while response_exposed is false, and identify the separate server-side defense needed.
