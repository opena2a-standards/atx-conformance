"""Vendored RFC 8785 (JSON Canonicalization Scheme) serializer.

Standard-library only, so it adds no dependency to the offline Python ATX
verifier. This is a clean-room implementation of the subset of RFC 8785 that
ATX v1.1 TBS objects exercise:

  * object members sorted by UTF-16 code-unit order of the member name
  * array element order preserved (never sorted)
  * minimal JSON string escaping (only ", \\, and the control range escape;
    every other code point, including all non-ASCII, emits as raw UTF-8)
  * integer numbers serialized as their shortest decimal form
  * arrays and objects at any nesting depth (serialized without recursion)

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
        "(trustScore is string-encoded as %%.6f). Got float %r. RFC 8785 ES6 "
        "number formatting is intentionally never exercised by this suite." % (n,)
    )


def _utf16_key(name: str) -> bytes:
    # RFC 8785 orders object member names by UTF-16 code units. Comparing the
    # big-endian UTF-16 byte serialization reproduces that ordering exactly,
    # including for code points above U+FFFF (which become surrogate pairs).
    return name.encode("utf-16-be")


class _Text(str):
    """Serialized text that _serialize has queued between the values it has
    still to serialize."""

    __slots__ = ()


def _serialize(value: Any) -> str:
    # Without recursion, so a deeply nested array or object does not exhaust
    # the stack. pending holds, last first, the values still to serialize and
    # the _Text that goes between them; each value is serialized in the same
    # order as a recursive descent would, so the same value raises first.
    out = []
    pending = [value]
    while pending:
        item = pending.pop()
        if type(item) is _Text:
            out.append(item)
        elif item is None:
            out.append("null")
        elif item is True:
            out.append("true")
        elif item is False:
            out.append("false")
        elif isinstance(item, str):
            out.append(_escape_string(item))
        elif isinstance(item, (int, float)):
            out.append(_serialize_number(item))
        elif isinstance(item, list):
            out.append("[")
            pending.append(_Text("]"))
            for i in range(len(item) - 1, -1, -1):
                pending.append(item[i])
                if i:
                    pending.append(_Text(","))
        elif isinstance(item, dict):
            out.append("{")
            pending.append(_Text("}"))
            items = sorted(item.items(), key=lambda kv: _utf16_key(kv[0]))
            for i in range(len(items) - 1, -1, -1):
                name, member = items[i]
                pending.append(member)
                pending.append(_Text(_escape_string(name) + ":"))
                if i:
                    pending.append(_Text(","))
        else:
            raise TypeError("unsupported JSON value of type %s" % type(item).__name__)
    return "".join(out)


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 byte serialization of value."""
    return _serialize(value).encode("utf-8")
