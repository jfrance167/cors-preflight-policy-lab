# Input and output contract — version1

Input root: exactly `schema_version` (integer1), `trusted_origins` (1–32 supported
canonical non-null origins, unique) and `cases` (1–100). Each case exactly:

| Field | Meaning/constraint |
|---|---|
| id | unique nonempty string,64 UTF-8 bytes maximum |
| origin | serialized caller origin,512 bytes; supported DNS HTTP(S) or null |
| credentials | omit, same-origin or include; every transaction modeled cross-origin |
| method | ASCII HTTP token up to16 bytes; modeled GET/HEAD/POST/PUT/DELETE |
| headers | request header pairs, at most32; duplicate names after lowercase rejected |
| preflight | null or response object; a null required preflight fails transmission |
| response | actual response object |
| effect_if_sent | strict Boolean; fictional assumption, never executes anything |

Response object: exactly integer status100–599 and header pairs. Each name up to64 bytes,
each value up to256 bytes; ASCII values, token names, no controls/lone surrogates.
ACAO/ACAC are singleton values: duplicates, commas and surrounding whitespace rejected.
ACAM/ACAH token lists reject empty/duplicate tokens; header tokens compare case-insensitively,
method tokens case-sensitively. Headers remain pairs until duplicate detection is complete.
Invalid later cases reject the whole input; no early report is released.

Strict JSON: at most128KiB raw UTF-8, depth8 outside strings, numeric tokens at most6
characters, integers only, duplicate keys rejected, no NaN/infinity or Boolean version/status.
Origin grammar is deliberately narrower than WHATWG URL; unsupported forms are explicit.
Uppercase/leading-zero/explicit-default ports and noncanonical labels are invalid data;
numeric/Unicode/IPv6 origins are unknown scope, never normalized into trusted identity.

Output root contains versions, simulation_kind, counts and per-case results. It reads no
expected labels. Each row has supported, preflight_required, preflight_passed,
actual_request_sent, response_exposed, intended_origin_allowed, fixture_effect and reasons.
Null means unmodeled/not applicable, not false. Unsupported processing leaves transmission,
exposure/effect unknown; supported-origin intent may still be known independently.

Preflight is required for unsafe method/header subset. If required, status2xx, successful
CORS sharing, unsafe-method allowance and unsafe-header allowance must all succeed.
Safelisted methods need no ACAM even when headers require preflight. Authorization always
needs explicit ACAH, wildcard headers/methods only match when credentials is not include.
Actual status does not need2xx. Actual CORS sharing is checked separately after transmission.

Reports are buffered/encoded and capped at512KiB before writing/printing. JSON escapes
non-ASCII; Markdown cells escape HTML and formatting/link/image syntax. Fresh output
creation refuses existing files/aliases. A local write failure is explicit exit3 and
can leave a partial new file; no existing report is overwritten. CLI exit2 signifies
valid evaluation with unknown cases, not a security pass or an execution failure.
