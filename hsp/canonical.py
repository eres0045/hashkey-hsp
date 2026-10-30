"""Canonical JSON (RFC 8785, JSON Canonicalization Scheme) for Cart Mandates.

The cart_hash is SHA-256 over this exact byte string, so the encoding must
be deterministic: object keys sorted by UTF-16 code units, no insignificant
whitespace, strings escaped per JCS, numbers per ECMAScript Number::toString.

Scope note: mandate payloads in this project carry only strings, integers,
booleans, nulls, arrays and objects, so the float branch below is a
best-effort ECMAScript-style rendering, not a full IEEE-754 implementation.
Non-ASCII strings are emitted as UTF-8 (never \\u-escaped, except for the
control characters JCS requires).
"""

import json

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}


def _utf16_key(key: str) -> bytes:
    """Sort key: the UTF-16BE encoding of the string (JCS key ordering)."""
    return key.encode("utf-16-be", "surrogatepass")


def _escape_string(value: str) -> str:
    out = ['"']
    for ch in value:
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _number(value) -> str:
    if isinstance(value, bool):
        raise TypeError("bool is not a number here")
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("non-finite numbers are not JSON")
        if value == int(value) and abs(value) < 1e21:
            return str(int(value))
        # ECMAScript-style shortest repr; Python repr matches for the
        # magnitudes used in this project (amounts are decimal strings).
        return repr(value)
    raise TypeError(f"unsupported number type: {type(value)!r}")


def canonical_dumps(value) -> str:
    """Return the RFC 8785 canonical JSON string for *value*."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _escape_string(value)
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_dumps(item) for item in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: _utf16_key(str(kv[0])))
        return "{" + ",".join(
            _escape_string(str(k)) + ":" + canonical_dumps(v) for k, v in items
        ) + "}"
    raise TypeError(f"not JSON-serializable: {type(value)!r}")


def canonical_json(value) -> bytes:
    """Return the canonical JSON as UTF-8 bytes (the cart_hash input)."""
    return canonical_dumps(value).encode("utf-8")


def canonical_compact(value) -> str:
    """Non-canonical compact JSON for HTTP bodies (key order preserved)."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
