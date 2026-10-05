# Security model

This lab operates only on owned fictional data and pure local reasoning. No socket,
HTTP client, shell, web service, cookie store or browser runner is part of runtime.
Untrusted origin/header/ID data never selects code or an external destination.
The CLI input/output filenames are trusted human controls, not fixture fields.

Assets: preserved files, bounded local resources, correct boundary explanations and
repeatable evidence. Inputs can contain malformed JSON, ambiguous headers, misleading
origins and Markdown/HTML syntax. Threats include parser ambiguity, generated-report
content injection, model/browser disagreement and overstating results as real defenses.

Controls: byte/depth/numeric/string/count limits; duplicate JSON and case-insensitive
header rejection; strict supported schemas; canonical restricted origins; separate
unsupported/invalid/protocol/intent results; all cases validated before reporting; fresh
exclusive output creation; escaped report cells; independent frozen labels and mutations.
Limitations: same-process Python callers and input/output path selection are trusted;
the CLI is not a hostile multi-user filesystem service. Local I/O failure can leave a
partial fresh report; it is never a successful run. No provenance/authenticity of a
caller-created fixture or its effect declaration is established.

CORS protocol rules govern modeled cross-origin request/response handling. They do not
authenticate the requester or authorize a server action. A request that is sent may have
an unreadable response; an application still needs appropriate server authorization and
CSRF protections. The model does not predict cookie attachment, SameSite, third-party
cookie settings or actual server processing.

Review priorities: contracts/origin ambiguity and duplicate headers; credential/wildcard
semantics; preflight versus actual status; partial unknown results; transmission/exposure/
application-intent separation; report safety and no-network boundary. Future browser or
server integration must receive its own review and evidence. Manual consequential-boundary
review remains before any separately authorized publication, merge or deployment.

No production-security certification, browser compatibility, live vulnerability finding
or universal CORS/CSRF protection is claimed. No external disclosure/email automation.
