"""No requests are made: evaluate a documented subset of synthetic CORS facts."""

from .contracts import TOKEN, Unsupported, headers, origin, response, validate

SAFE_METHODS = frozenset({"GET", "HEAD", "POST"})
METHODS = SAFE_METHODS | {"PUT", "DELETE"}
CONTENT_TYPES = frozenset({"text/plain", "application/x-www-form-urlencoded", "multipart/form-data"})


def _exposure(request_origin, credentials, fields):
    allowed = fields.get("access-control-allow-origin")
    # This exact comparison must never become a hostname substring match.
    if credentials != "include" and allowed == "*":
        return True
    if allowed != request_origin:
        return False
    # Include mode cannot use '*' even when no actual cookie exists in a fixture.
    if credentials == "include":
        return allowed != "*" and fields.get("access-control-allow-credentials") == "true"
    return True


def _tokens(fields, name):
    return [part.strip() for part in fields.get(name, "").split(",") if part.strip()]


def _unsafe_headers(fields):
    unsafe = []
    for name, value in fields.items():
        if name == "content-type":
            if value in CONTENT_TYPES:
                continue
            if value != "application/json":
                raise Unsupported("UNSUPPORTED_CONTENT_TYPE")
        elif name not in ("authorization", "x-test"):
            raise Unsupported("UNSUPPORTED_REQUEST_HEADER")
        unsafe.append(name)
    return unsafe


def _status_supported(status):
    if status < 200 or 300 <= status < 400:
        raise Unsupported("UNSUPPORTED_INFORMATIONAL_OR_REDIRECT_STATUS")


def _case(case, trusted):
    result = {"id": case["id"], "supported": True, "preflight_required": None,
              "preflight_passed": None, "actual_request_sent": None,
              "response_exposed": None, "intended_origin_allowed": None,
              "fixture_effect": None, "reason_codes": []}
    try:
        request_origin = origin(case["origin"])
        result["intended_origin_allowed"] = request_origin in trusted
        # The lab only models cross-origin transactions; target is fictional
        # and separate from every caller. It does not infer same-site cookies.
        if case["method"] not in METHODS:
            raise Unsupported("UNSUPPORTED_METHOD")
        unsafe = _unsafe_headers(headers(case["headers"]))
        _status_supported(case["response"]["status"])
        if case["preflight"] is not None:
            _status_supported(case["preflight"]["status"])
        required = case["method"] not in SAFE_METHODS or bool(unsafe)
        if not required and case["preflight"] is not None:
            raise Unsupported("UNSUPPORTED_UNNEEDED_PREFLIGHT")
        result["preflight_required"] = required
        sent = True
        if required:
            preflight = case["preflight"]
            passed = preflight is not None
            if passed:
                fields = response(preflight)
                passed = 200 <= preflight["status"] < 300 and _exposure(request_origin, case["credentials"], fields)
                methods = _tokens(fields, "access-control-allow-methods")
                # Safelisted GET/POST triggered by unsafe headers do not need
                # explicit method permission. Method tokens are case-sensitive.
                if case["method"] not in SAFE_METHODS:
                    passed = passed and (case["method"] in methods or
                                        (case["credentials"] != "include" and "*" in methods))
                allowed_headers = [t.lower() for t in _tokens(fields, "access-control-allow-headers")]
                for name in unsafe:
                    matched = name in allowed_headers or (name != "authorization"
                              and case["credentials"] != "include" and "*" in allowed_headers)
                    passed = passed and matched
            result["preflight_passed"] = bool(passed)
            sent = bool(passed)
        exposed = sent and _exposure(request_origin, case["credentials"], response(case["response"]))
        result.update(actual_request_sent=sent, response_exposed=exposed,
                      fixture_effect=sent and case["effect_if_sent"])
        result["reason_codes"] = ["RESPONSE_EXPOSED" if exposed else "RESPONSE_NOT_EXPOSED",
                                  "APPLICATION_ORIGIN_ALLOWED" if result["intended_origin_allowed"]
                                  else "APPLICATION_ORIGIN_NOT_ALLOWED"]
        if required:
            result["reason_codes"].append("PREFLIGHT_PASSED" if sent else "PREFLIGHT_FAILED")
        if sent and not exposed:
            result["reason_codes"].append("TRANSMISSION_NOT_PREVENTED_BY_RESPONSE_CHECK")
    except Unsupported as exc:
        result["supported"] = False
        result["reason_codes"] = [str(exc)]
    return result


def evaluate(document):
    """All-or-nothing validation, then pure local model evaluation; no labels read."""
    validate(document)
    rows = [_case(case, frozenset(document["trusted_origins"])) for case in document["cases"]]
    return {"schema_version": 1, "component_version": "0.1.0",
            "simulation_kind": "restricted_offline_cors_model_not_browser",
            "case_count": len(rows), "supported_count": sum(row["supported"] for row in rows),
            "unsupported_count": sum(not row["supported"] for row in rows), "results": rows}
