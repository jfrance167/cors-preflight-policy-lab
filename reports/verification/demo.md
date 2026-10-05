# Restricted offline CORS model

No browser/network/server testing performed.

| id | supported | preflight_required | preflight_passed | actual_request_sent | response_exposed | intended_origin_allowed | fixture_effect |
| --- | --- | --- | --- | --- | --- | --- | --- |
| trusted-get | True | False | None | True | True | True | False |
| trusted-403 | True | False | None | True | True | True | False |
| trusted-404 | True | False | None | True | True | True | False |
| wrong-scheme | True | False | None | True | False | False | False |
| wrong-port | True | False | None | True | False | False | False |
| wrong-subdomain | True | False | None | True | False | False | False |
| suffix-confusion | True | False | None | True | False | False | False |
| reflect-untrusted | True | False | None | True | True | False | False |
| null-no-share | True | False | None | True | False | False | False |
| null-reflected | True | False | None | True | True | False | False |
| public-wildcard | True | False | None | True | True | False | False |
| credentials-wildcard | True | False | None | True | False | True | False |
| credentials-exact | True | False | None | True | True | True | False |
| credentials-missing | True | False | None | True | False | True | False |
| credentials-case | True | False | None | True | False | True | False |
| put-allowed | True | True | True | True | True | True | False |
| put-denied | True | True | False | False | False | True | False |
| preflight-403 | True | True | False | False | False | True | False |
| get-header-no-method | True | True | True | True | True | True | False |
| post-json-no-method | True | True | True | True | True | True | False |
| header-denied | True | True | False | False | False | True | False |
| authorization-wildcard | True | True | False | False | False | True | False |
| authorization-explicit | True | True | True | True | True | True | False |
| header-wildcard-omit | True | True | True | True | True | True | False |
| header-wildcard-include | True | True | False | False | False | True | False |
| method-wildcard-omit | True | True | True | True | True | True | False |
| method-wildcard-include | True | True | False | False | False | True | False |
| post-sent-unreadable | True | False | None | True | False | True | True |
| preflight-pass-actual-fail | True | True | True | True | False | True | True |
| unsupported-safe-header | False | None | None | None | None | True | None |
| unsupported-redirect | False | None | None | None | None | True | None |
| wildcard-acac-omit | True | False | None | True | True | True | False |

Unsupported values are unknown, not denials. Fixture effects are memory-only.
