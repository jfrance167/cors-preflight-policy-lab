# Learning notes

Response visibility cannot authorize or undo a server action. Compare sent/unreadable
POST with failed-preflight PUT. A scripted effect is a fixture assumption, not proof a
real server executes or blocks it.

ACAO wildcard plus include fails protocol sharing, whereas reflecting any origin plus
ACAC true can satisfy it while violating private policy. Same label "CORS allowed" would
hide this distinction. A readable403 response can still say the server denied an action.

Opaque origins serialize to null; that string is not an identity. Strict limited origin
grammar is easier to verify than incomplete emulation of a browser's URL algorithm.

Tests/fixtures require trusted reasoning: local Ollama's six draft ideas confused browser
checks and server rejection. Preserve rejected drafts and review primary sources. Codex
retained security judgment; no weak draft or claimed measured token saving was shipped.

Reports are another trust boundary: escaping table bars alone does not stop HTML or
Markdown image/link injection. ECC review added a concrete rendering regression.

Optional exercise: identify one legitimate read, one protocol sharing failure, one
application-intent violation and one unsupported case in the demo; explain the difference.
