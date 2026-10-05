"""Bounded strict JSON and canonical origins, without browser URL emulation."""

import json
import re

INPUT_BYTES = 131_072
OUTPUT_BYTES = 524_288
TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", re.ASCII)
HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)


class Invalid(ValueError):
    """Invalid supported-contract data; reject the whole document."""


class Unsupported(Invalid):
    """Explicit model scope limitation; not a protocol denial."""


def text(value, limit=256):
    if type(value) is not str:
        raise Invalid("STRING_REQUIRED")
    try:
        size = len(value.encode("utf-8", "strict"))
    except UnicodeError as exc:
        raise Invalid("INVALID_UNICODE") from exc
    if size > limit or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise Invalid("TEXT_LIMIT_OR_CONTROL")
    return value


def keys(value, required):
    if type(value) is not dict or set(value) != set(required):
        raise Invalid("INVALID_SCHEMA")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Invalid("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _integer(token):
    if len(token) > 6:
        raise Invalid("NUMERIC_TOKEN_LIMIT")
    return int(token)


def _noninteger(_):
    raise Invalid("INTEGER_ONLY")


def parse(raw):
    """Reject byte/depth/numeric/duplicate constraints before case evaluation."""
    if type(raw) is not bytes or len(raw) > INPUT_BYTES:
        raise Invalid("INPUT_LIMIT")
    try:
        source = raw.decode("utf-8", "strict")
        quoted = escaped = False
        depth = 0
        for char in source:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                if depth > 8:
                    raise Invalid("JSON_DEPTH")
            elif char in "]}":
                depth -= 1
        return json.loads(source, object_pairs_hook=_pairs, parse_int=_integer,
                          parse_float=_noninteger, parse_constant=_noninteger)
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, Invalid):
            raise
        raise Invalid("INVALID_JSON") from exc


def origin(value):
    """Accept serialized canonical HTTP(S) DNS origins or opaque marker null.

    No urlsplit normalization: it is not the browser URL parser. Default ports
    must already be omitted; numeric hosts and unsupported schemes are not guessed.
    """
    text(value, 512)
    if value == "null":
        return value
    if not value.isascii():
        raise Unsupported("UNSUPPORTED_ORIGIN_UNICODE")
    if any(c in value for c in "/?#@\\ \t") and not value.startswith(("http://", "https://")):
        raise Invalid("INVALID_ORIGIN")
    match = re.fullmatch(r"(http|https)://([^/:?#@\\\s]+)(?::([0-9]+))?", value, re.ASCII)
    if not match:
        if value.startswith(("http://[", "https://[", "file:", "data:", "blob:")):
            raise Unsupported("UNSUPPORTED_ORIGIN_KIND")
        raise Invalid("NONCANONICAL_ORIGIN")
    scheme, host, port = match.groups()
    labels = host.split(".")
    if len(host) > 253 or len(labels) < 2 or any(not HOST_LABEL.fullmatch(label) for label in labels):
        raise Invalid("NONCANONICAL_HOST")
    # Browser numeric-host parsing has surprising legacy forms; exclude numeric
    # final labels, including hexadecimal forms, instead of treating them as DNS.
    if labels[-1].isdigit() or re.fullmatch(r"0x[0-9a-f]+", labels[-1]):
        raise Unsupported("UNSUPPORTED_NUMERIC_HOST")
    if port is not None:
        if len(port) > 5 or port.startswith("0") or not 1 <= int(port) <= 65535:
            raise Invalid("NONCANONICAL_PORT")
        if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
            raise Invalid("DEFAULT_PORT_NOT_SERIALIZED")
    return value


def headers(value):
    """Header pairs preserve duplicate detection before creating a lookup map."""
    if type(value) is not list or len(value) > 32:
        raise Invalid("HEADER_LIMIT")
    result = {}
    for pair in value:
        if type(pair) is not list or len(pair) != 2:
            raise Invalid("INVALID_HEADER_PAIR")
        name, field = pair
        text(name, 64)
        text(field)
        if not TOKEN.fullmatch(name) or not field.isascii():
            raise Invalid("INVALID_HEADER")
        lowered = name.lower()
        if lowered in result:
            raise Invalid("DUPLICATE_HEADER")
        result[lowered] = field
    return result


def response(value):
    keys(value, {"status", "headers"})
    if type(value["status"]) is not int or not 100 <= value["status"] <= 599:
        raise Invalid("INVALID_STATUS")
    result = headers(value["headers"])
    for name in ("access-control-allow-origin", "access-control-allow-credentials"):
        if name in result and ("," in result[name] or result[name] != result[name].strip()):
            raise Invalid("AMBIGUOUS_SINGLETON_HEADER")
    for name in ("access-control-allow-methods", "access-control-allow-headers"):
        if name in result:
            tokens = result[name].split(",") if result[name] else []
            if (len(tokens) > 32 or any(not TOKEN.fullmatch(t.strip()) for t in tokens)
                    or len({t.strip().lower() if name.endswith("headers") else t.strip()
                            for t in tokens}) != len(tokens)):
                raise Invalid("AMBIGUOUS_TOKEN_LIST")
    return result


def validate(document):
    """Validate every case before producing any result or output file."""
    keys(document, {"schema_version", "trusted_origins", "cases"})
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise Invalid("INVALID_VERSION")
    allowed = document["trusted_origins"]
    if type(allowed) is not list or not 1 <= len(allowed) <= 32:
        raise Invalid("POLICY_LIMIT")
    for value in allowed:
        if origin(value) == "null":
            raise Invalid("OPAQUE_ORIGIN_NOT_TRUSTED")
    if len(set(allowed)) != len(allowed):
        raise Invalid("DUPLICATE_POLICY_ORIGIN")
    cases = document["cases"]
    if type(cases) is not list or not 1 <= len(cases) <= 100:
        raise Invalid("CASE_LIMIT")
    identifiers = set()
    for case in cases:
        keys(case, {"id", "origin", "credentials", "method", "headers", "preflight", "response", "effect_if_sent"})
        name = text(case["id"], 64)
        if not name or name in identifiers:
            raise Invalid("DUPLICATE_OR_EMPTY_ID")
        identifiers.add(name)
        try:
            origin(case["origin"])
        except Unsupported:
            pass
        text(case["credentials"], 16)
        if case["credentials"] not in ("omit", "same-origin", "include"):
            raise Invalid("INVALID_CREDENTIALS")
        if not TOKEN.fullmatch(text(case["method"], 16)):
            raise Invalid("INVALID_METHOD")
        headers(case["headers"])
        response(case["response"])
        if case["preflight"] is not None:
            response(case["preflight"])
        if type(case["effect_if_sent"]) is not bool:
            raise Invalid("BOOLEAN_REQUIRED")
    return document
