"""Vendored RFC 8785 (JSON Canonicalization Scheme) serializer.

Standard-library only, so the Python ATX verifier keeps its zero-dependency
offline promise. This is a clean-room implementation of the subset of RFC 8785
that ATX v1.1 TBS objects exercise:

  * object members sorted by UTF-16 code-unit order of the member name
  * array element order preserved (never sorted)
  * minimal JSON string escaping (only ", \\, and the control range escape;
    every other code point, including all non-ASCII, emits as raw UTF-8)
  * integer numbers serialized as their shortest decimal form

ATX v1.1 deliberately carries NO JSON floating-point numbers in the TBS:
trustScore is string-encoded (%.6f) precisely so the ECMAScript/Ryu number
formatting of RFC 8785 section 3.2.2.3 never has to run cross-language. This
module therefore refuses non-integer floats loudly rather than risk a silent
divergence from the Go and TypeScript legs. The byte-agreement gate
(../run-agreement.sh) is what guarantees this module stays in lockstep with
github.com/gowebpki/jcs and erdtman/canonicalize.

Reference: https://www.rfc-editor.org/rfc/rfc8785
"""

from __future__ import annotations

from typing import Any

# Control characters with dedicated short escapes per JSON / RFC 8785.
_SHORT_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def _escape_string(s: str) -> str:
    out = []
    for ch in s:
        code = ord(ch)
        if code in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[code])
        elif code < 0x20:
            out.append("\\u%04x" % code)
        else:
            # All other code points, including every non-ASCII character,
            # are emitted literally; the final UTF-8 encoding carries them.
            out.append(ch)
    return '"' + "".join(out) + '"'


def _serialize_number(n: Any) -> str:
    # bool is a subclass of int; reject it (JSON booleans are handled by _serialize).
    if isinstance(n, bool):
        raise TypeError("booleans are not numbers")
    if isinstance(n, int):
        return str(n)
    raise NotImplementedError(
        "ATX v1.1 TBS must not contain JSON floating-point numbers "
        "(trustScore is string-encoded as %.6f). Got float %r. RFC 8785 ES6 "
        "number formatting is intentionally never exercised by this suite." % n
    )


def _utf16_key(name: str) -> bytes:
    # RFC 8785 orders object member names by UTF-16 code units. Comparing the
    # big-endian UTF-16 byte serialization reproduces that ordering exactly,
    # including for code points above U+FFFF (which become surrogate pairs).
    return name.encode("utf-16-be")


def _serialize(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _escape_string(value)
    if isinstance(value, (int, float)):
        return _serialize_number(value)
    if isinstance(value, list):
        return "[" + ",".join(_serialize(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: _utf16_key(kv[0]))
        return "{" + ",".join(_escape_string(k) + ":" + _serialize(v) for k, v in items) + "}"
    raise TypeError("unsupported JSON value of type %s" % type(value).__name__)


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 byte serialization of value."""
    return _serialize(value).encode("utf-8")
