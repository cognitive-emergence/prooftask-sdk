"""Strict JSON input and RFC 8785 canonical output (standards/canonical-json.md).

Numbers are IEEE 754 binary64, so every JSON number is read as a Python float.
Booleans are kept apart from numbers everywhere (Python treats True == 1).
"""
import json
from decimal import Decimal
import math

MAX_CANONICAL_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 64
MAX_VALUES = 100000


class InputError(ValueError):
    """A registered input reason code (INVALID_JSON, DUPLICATE_KEY, ...)."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _check_unicode(text):
    # Python decodes a lone \ud800 escape to a lone surrogate code point; RFC 8785 input forbids it.
    for ch in text:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            raise InputError("INVALID_UNICODE")


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise InputError("DUPLICATE_KEY")
        out[key] = value
    return out


def _bad_constant(_name):
    raise InputError("NON_FINITE_NUMBER")


def _number(text):
    value = float(text)
    if not math.isfinite(value):
        raise InputError("NON_FINITE_NUMBER")
    return value


def _bounds(value):
    count = 0
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        count += 1
        if count > MAX_VALUES or depth > MAX_DEPTH:
            raise InputError("LIMIT_EXCEEDED")
        if isinstance(item, str):
            _check_unicode(item)
        elif isinstance(item, dict):
            for key, child in item.items():
                _check_unicode(key)
                stack.append((child, depth + 1))
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)


def parse_text(text, max_bytes=MAX_CANONICAL_BYTES):
    if len(text.encode("utf-8", "surrogatepass")) > max_bytes:
        raise InputError("LIMIT_EXCEEDED")
    if text.startswith("﻿"):
        raise InputError("INVALID_JSON")
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_float=_number, parse_int=_number,
                           parse_constant=_bad_constant)
    except InputError:
        raise
    except (ValueError, RecursionError):
        raise InputError("INVALID_JSON")
    _bounds(value)
    return value


def decode_utf8(data):
    try:
        return data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise InputError("INVALID_UTF8")


def parse_bytes(data, max_bytes=MAX_CANONICAL_BYTES):
    if len(data) > max_bytes:
        raise InputError("LIMIT_EXCEEDED")
    return parse_text(decode_utf8(data), max_bytes)


# ---------- RFC 8785 serialization ----------
_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _string(value):
    _check_unicode(value)
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


def es_number(value):
    """ECMAScript Number::toString for a finite binary64 value (RFC 8785 section 3.2.2.3)."""
    if not math.isfinite(value):
        raise InputError("NON_FINITE_NUMBER")
    if value == 0:
        return "0"
    if value < 0:
        return "-" + es_number(-value)
    _sign, digit_tuple, exponent = Decimal(repr(float(value))).as_tuple()
    digits = "".join(str(d) for d in digit_tuple).lstrip("0")
    while digits.endswith("0"):
        digits, exponent = digits[:-1], exponent + 1
    point = exponent + len(digits)
    k, n = len(digits), point
    if k <= n <= 21:
        return digits + "0" * (n - k)
    if 0 < n <= 21:
        return digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + digits
    e = n - 1
    sign = "+" if e >= 0 else "-"
    head = digits[0] + ("." + digits[1:] if k > 1 else "")
    return "%se%s%d" % (head, sign, abs(e))


def _utf16_key(key):
    return key.encode("utf-16-be", "surrogatepass")


def canonical(value):
    """RFC 8785 JCS text of a JSON value."""
    count = [0]

    def emit(item, depth):
        count[0] += 1
        if count[0] > MAX_VALUES or depth > MAX_DEPTH:
            raise InputError("LIMIT_EXCEEDED")
        if item is None:
            return "null"
        if item is True:
            return "true"
        if item is False:
            return "false"
        if isinstance(item, (int, float)):
            return es_number(float(item))
        if isinstance(item, str):
            return _string(item)
        if isinstance(item, list):
            return "[" + ",".join(emit(child, depth + 1) for child in item) + "]"
        if isinstance(item, dict):
            keys = sorted(item.keys(), key=_utf16_key)
            return "{" + ",".join(_string(k) + ":" + emit(item[k], depth + 1) for k in keys) + "}"
        raise InputError("UNSUPPORTED_VALUE")

    text = emit(value, 0)
    if len(text.encode("utf-8")) > MAX_CANONICAL_BYTES:
        raise InputError("LIMIT_EXCEEDED")
    return text


def canonical_bytes(value):
    return canonical(value).encode("utf-8")


def same(a, b):
    """JSON equality (no bool/number confusion)."""
    return canonical(a) == canonical(b)


def is_integer(value, minimum=None, maximum=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    if not float(value).is_integer() or abs(value) > 2 ** 53 - 1:
        return False
    return (minimum is None or value >= minimum) and (maximum is None or value <= maximum)

