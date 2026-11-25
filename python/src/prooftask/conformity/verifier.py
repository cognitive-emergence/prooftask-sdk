"""Offline Conformity 1.0/1.1/1.2 verifier written from the published specification (standards/, including the
verification procedure of standards/conformity-verification-1.2.md), plus the unpublished 1.3 candidate (reporter
attribution, standards/conformity-record-1.3.md and conformity-verification-1.3.md) and the implementer's guide
(docs/developers/CONFORMITY_VERIFIER.md). It is a second, independent reading of the format:
it shares no code with the JavaScript reference verifier.

Scope: Records as full Packages and as partial SD-JWT presentations, Status statements and Summaries, with
issuer keys the relying party supplies. Not implemented: anchoring evidence (`evidence/`, package standard 1.2);
a 1.1 or 1.2 Package that carries it raises UnsupportedEvidence instead of returning a report without it.

No network access, no system clock unless the caller omits checkedAt for a Status, no product-specific handlers.
"""
import base64
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone

from . import _ed25519
from ._json import InputError, canonical, canonical_bytes, decode_utf8, is_integer, parse_bytes, parse_text, same

RECORD_10 = "https://humanjudgment.org/ns/conformity-record/1.0"
RECORD_11 = "https://humanjudgment.org/ns/conformity-record/1.1"
RECORD_12 = "https://humanjudgment.org/ns/conformity-record/1.2"
RECORD_13 = "https://humanjudgment.org/ns/conformity-record/1.3"
SUPPLEMENTED = (RECORD_11, RECORD_12, RECORD_13)
PACKAGE = "https://humanjudgment.org/ns/conformity-package/1.0"
SUMMARY = "https://humanjudgment.org/ns/conformity-summary/1.0"
STATUS = "https://humanjudgment.org/ns/conformity-status/1.0"
REPORT_10 = "https://humanjudgment.org/ns/conformity-verification/1.0"
REPORT_11 = "https://humanjudgment.org/ns/conformity-verification/1.1"
REPORT_12 = "https://humanjudgment.org/ns/conformity-verification/1.2"
REPORT_13 = "https://humanjudgment.org/ns/conformity-verification/1.3"
REPORTS = {RECORD_10: REPORT_10, RECORD_11: REPORT_11, RECORD_12: REPORT_12, RECORD_13: REPORT_13}
REPORTER_LIMITATION = "ACTOR_ATTRIBUTION_REPORTER_ASSERTION"
REPORTER_STATEMENT_SCHEME = "urn:conformity:reporter-statement"
ACCEPTERMS = "https://humanjudgment.org/ns/accepterms/2027"
NATIVE_TSTO_PROFILE = "https://humanjudgment.org/profiles/conformity/1.0"
KNOWN_KINDS = ("AGREEMENT", "DELIVERY", "DECISION", "EVALUATION")
SD_RESERVED = ("_sd", "_sd_alg", "...")

_HERE = os.path.dirname(os.path.abspath(__file__))


def _data(name):
    with open(os.path.join(_HERE, "data", name), "rb") as handle:
        return parse_bytes(handle.read())


# Reports use the current catalog (1.3); a record's limitations come from the catalog of its own version.
REASONS = frozenset(_data("conformity-reasons-1.3.json")["reasons"])
LIMITATION_CATALOGS = {RECORD_10: frozenset(_data("conformity-reasons-1.1.json")["reasons"]), RECORD_11: frozenset(_data("conformity-reasons-1.1.json")["reasons"]),
                       RECORD_12: frozenset(_data("conformity-reasons-1.2.json")["reasons"]), RECORD_13: REASONS}
SCHEMAS = {RECORD_10: _data("conformity-record.schema.json"), RECORD_11: _data("conformity-record-1.1.schema.json"),
           RECORD_12: _data("conformity-record-1.2.schema.json"), RECORD_13: _data("conformity-record-1.3.schema.json"),
           STATUS: _data("conformity-status.schema.json"), SUMMARY: _data("conformity-summary.schema.json")}


class Fail(Exception):
    """One registered reason code; the artifact is INVALID."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


class UnsupportedEvidence(Exception):
    """The Package carries anchoring evidence, which this verifier does not implement."""


def demand(ok, code):
    if not ok:
        raise Fail(code)


# ---------- encodings ----------
_B64URL = re.compile(r"[A-Za-z0-9_-]+\Z")


def b64url_decode(text, allow_empty=False):
    if allow_empty and text == "":
        return b""
    demand(isinstance(text, str) and _B64URL.match(text) is not None and len(text) % 4 != 1, "INVALID_BASE64URL")
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    demand(b64url(data) == text, "INVALID_BASE64URL")  # canonical: no stray trailing bits
    return data


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def json_digest(value):
    """`sha256:` + lowercase hex over the JCS bytes (canonical-json.md)."""
    return "sha256:" + sha256_hex(canonical_bytes(value))


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_decode(text):
    demand(isinstance(text, str) and 0 < len(text) <= 200 and all(c in _B58 for c in text), "INVALID_BASE58")
    number = 0
    for char in text:
        number = number * 58 + _B58.index(char)
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\0" * (len(text) - len(text.lstrip("1"))) + body


# ---------- time ----------
_CANONICAL_TIME = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z\Z", re.ASCII)
_RFC3339 = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?(Z|[+-]\d{2}:\d{2})\Z", re.ASCII)
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _instant(match, offset="Z"):
    year, month, day, hour, minute, second = (int(match.group(i)) for i in range(1, 7))
    fraction = match.group(7) or "0"
    stamp = datetime(year, month, day, hour, minute, second, int(fraction.ljust(3, "0")) * 1000, tzinfo=timezone.utc)
    if offset != "Z":
        sign = 1 if offset[0] == "+" else -1
        stamp -= sign * timedelta(hours=int(offset[1:3]), minutes=int(offset[4:6]))
    return stamp


def epoch_ms(text):
    """Milliseconds of an RFC 3339 instant, or None (used only to compare with a JWT NumericDate)."""
    match = _RFC3339.match(text) if isinstance(text, str) else None
    if not match:
        return None
    try:
        delta = _instant(match, match.group(8)) - _EPOCH
    except ValueError:
        return None
    return (delta.days * 86400 + delta.seconds) * 1000 + delta.microseconds // 1000


def canonical_time(text):
    """A canonical UTC timestamp YYYY-MM-DDTHH:MM:SS.mmmZ naming a real calendar instant."""
    match = _CANONICAL_TIME.match(text) if isinstance(text, str) else None
    if not match or int(match.group(1)) == 0:
        return False
    try:
        _instant(match)
    except ValueError:
        return False
    return True


def require_time(text):
    demand(canonical_time(text), "INVALID_CONFORMITY_INPUT")


def time_of_ms(ms):
    stamp = _EPOCH + timedelta(milliseconds=ms)
    return stamp.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (stamp.microsecond // 1000)


# ---------- issuer identity ----------
_HOST = re.compile(r"[a-z0-9.-]+(?::[0-9]{1,5})?\Z")


def issuer_did(origin):
    """did:web for a canonical HTTPS origin (issuer-discovery.md); raises for anything that is not one."""
    demand(isinstance(origin, str) and origin.startswith("https://"), "INVALID_ISSUER_ORIGIN")
    host = origin[len("https://"):]
    demand(_HOST.match(host) is not None and not host.startswith(".") and ".." not in host
           and not host.endswith(":443"), "INVALID_ISSUER_ORIGIN")
    if ":" in host:
        demand(0 < int(host.split(":")[1]) < 65536 and host.split(":")[1] == str(int(host.split(":")[1])), "INVALID_ISSUER_ORIGIN")
    return "did:web:" + host.replace(":", "%3A")


def issuer_origin_of_did(did):
    demand(isinstance(did, str) and did.startswith("did:web:"), "ISSUER_IDENTIFIER_MISMATCH")
    origin = "https://" + did[len("did:web:"):].replace("%3A", ":").replace("%3a", ":")
    try:
        demand(issuer_did(origin) == did, "ISSUER_IDENTIFIER_MISMATCH")
    except Fail:
        raise Fail("ISSUER_IDENTIFIER_MISMATCH")
    return origin


# ---------- trusted keys ----------
class KeyPolicy:
    """The relying party's issuer keys. `weigh_revoked` lets a REVOKED key verify historical records whose use is
    then judged against independent time (package standard 1.2); Status and Summary never set it."""

    def __init__(self, trust, weigh_revoked=False):
        issuers = trust.get("issuers") if isinstance(trust, dict) else None
        if not isinstance(issuers, dict):
            raise Fail("RESULT_TRUST_INVALID")
        self.issuers = issuers
        self.weigh_revoked = weigh_revoked
        self.revoked_uses = []

    def key(self, origin, kid, at):
        issuer_did(origin)
        require_time(at)
        matching = [k for k in self.issuers.get(origin, []) if isinstance(k, dict) and k.get("id") == kid]
        demand(len(matching) == 1, "UNTRUSTED_ISSUER_KEY")
        k = matching[0]
        valid_from, valid_until, status = k.get("validFrom"), k.get("validUntil"), k.get("status")
        for bound in (valid_from, valid_until):
            if bound is not None:
                require_time(bound)
        if status == "REVOKED" and self.weigh_revoked:
            demand(valid_from is None or at >= valid_from, "ISSUER_KEY_NOT_VALID_AT_ISSUANCE")
            self.revoked_uses.append(valid_until)
        else:
            demand(status in ("ACTIVE", "RETIRED") and (valid_from is None or at >= valid_from)
                   and (valid_until is None or at < valid_until), "ISSUER_KEY_NOT_VALID_AT_ISSUANCE")
        raw = _ed25519.public_key_from_pem(k.get("publicKeyPem", "")) if isinstance(k.get("publicKeyPem"), str) else None
        demand(raw is not None, "UNSUPPORTED_KEY_TYPE")
        return raw


def revoked_decision(uses, independent_time=None):
    """Status and extra reasons for records whose signatures needed a REVOKED key (package-1.2)."""
    if not uses:
        return "VERIFIED_WITH_LIMITATIONS", []
    if independent_time is not None and all(u is not None and independent_time < u for u in uses):
        return "VERIFIED_WITH_LIMITATIONS", ["ISSUER_KEY_REVOKED_PRE_EXPOSURE_PROVEN"]
    return "INDETERMINATE", ["ISSUER_KEY_REVOKED_TIME_UNPROVEN"] + (
        ["HISTORICAL_KEY_VALIDITY_UNKNOWN"] if any(u is None for u in uses) else [])


# ---------- compact JWS ----------
def verify_compact_jwt(token, keys):
    parts = token.split(".")
    demand(len(parts) == 3, "INVALID_JWT")
    header_bytes = b64url_decode(parts[0])
    demand(len(header_bytes) <= 4096, "LIMIT_EXCEEDED")
    header, payload = parse_bytes(header_bytes), parse_bytes(b64url_decode(parts[1]))
    demand(isinstance(header, dict) and header.get("alg") == "EdDSA" and isinstance(header.get("kid"), str)
           and set(header) <= {"alg", "kid", "typ"}, "UNSUPPORTED_JWT_HEADER")
    iat = payload.get("iat") if isinstance(payload, dict) else None
    demand(isinstance(payload, dict) and isinstance(payload.get("iss"), str) and not isinstance(iat, bool)
           and isinstance(iat, (int, float)) and is_integer(iat * 1000), "INVALID_JWT_CLAIMS")
    signature = b64url_decode(parts[2])
    demand(len(signature) == 64, "INVALID_SIGNATURE")
    at = time_of_ms(int(iat * 1000))
    public_key = keys.key(payload["iss"], header["kid"], at)
    demand(_ed25519.verify(public_key, (parts[0] + "." + parts[1]).encode("ascii"), signature), "INVALID_SIGNATURE")
    return header, payload


# ---------- SD-JWT (RFC 9901 profile of conformity-record.md) ----------
def _contains_reserved(value):
    if isinstance(value, dict):
        return any(k in SD_RESERVED or _contains_reserved(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_contains_reserved(v) for v in value)
    return False


def resolve_disclosures(payload, encoded_list):
    available = {}
    for encoded in encoded_list:
        decoded = parse_bytes(b64url_decode(encoded))
        demand(isinstance(decoded, list) and len(decoded) in (2, 3) and isinstance(decoded[0], str), "INVALID_DISCLOSURE")
        try:
            salt = b64url_decode(decoded[0])
        except Fail:
            raise Fail("INVALID_DISCLOSURE")
        demand(len(salt) >= 16, "INVALID_DISCLOSURE")
        if len(decoded) == 3:
            demand(isinstance(decoded[1], str) and decoded[1] not in ("_sd", "..."), "INVALID_DISCLOSURE")
        digest = b64url(hashlib.sha256(encoded.encode("ascii")).digest())
        demand(digest not in available, "DUPLICATE_DISCLOSURE")
        available[digest] = decoded
    referenced, used, missing = set(), set(), []

    def take(digest, in_array):
        demand(isinstance(digest, str), "INVALID_DISCLOSURE_DIGEST")
        try:
            demand(len(b64url_decode(digest)) == 32, "INVALID_DISCLOSURE_DIGEST")
        except Fail:
            raise Fail("INVALID_DISCLOSURE_DIGEST")
        demand(digest not in referenced, "DUPLICATE_DISCLOSURE_DIGEST")
        referenced.add(digest)
        found = available.get(digest)
        if found is None:
            missing.append(digest)
            return None
        demand(in_array == (len(found) == 2), "DISCLOSURE_LOCATION_MISMATCH")
        used.add(digest)
        return found

    def walk(value, depth):
        demand(depth <= 64, "DISCLOSURE_DEPTH_EXCEEDED")
        if isinstance(value, list):
            out = []
            for item in value:
                if isinstance(item, dict) and "..." in item:
                    demand(len(item) == 1, "INVALID_ARRAY_DISCLOSURE")
                    found = take(item["..."], True)
                    if found is not None:
                        out.append(walk(found[1], depth + 1))
                else:
                    out.append(walk(item, depth + 1))
            return out
        if isinstance(value, dict):
            demand("..." not in value, "INVALID_ARRAY_DISCLOSURE")
            out = {k: walk(v, depth + 1) for k, v in value.items() if k not in ("_sd", "_sd_alg")}
            if "_sd" in value:
                demand(isinstance(value["_sd"], list), "INVALID_DISCLOSURE_DIGEST")
                for digest in value["_sd"]:
                    found = take(digest, False)
                    if found is not None:
                        demand(found[1] not in out, "DUPLICATE_CLAIM")
                        out[found[1]] = walk(found[2], depth + 1)
            if "_sd_alg" in value:
                demand(depth == 0 and value["_sd_alg"] == "sha-256", "UNSUPPORTED_SD_ALGORITHM")
            return out
        return value

    resolved = walk(payload, 0)
    demand(len(used) == len(available), "UNREFERENCED_DISCLOSURE")
    # Nested commitments are forbidden in this profile: no disclosed value may carry SD-JWT syntax.
    demand(not any(_contains_reserved(d[-1]) for d in available.values()), "NESTED_DISCLOSURE_FORBIDDEN")
    return resolved, len(used), len(referenced), missing


# ---------- bounded JSON Schema subset (the vocabulary the published schemas use) ----------
def _pattern(pattern):
    # ECMAScript `$` matches only at the end; Python's also matches before a final newline. `\d` is ASCII only.
    if pattern.endswith("$") and not pattern.endswith("\\$"):
        pattern = pattern[:-1] + r"\Z"
    return re.compile(pattern, re.ASCII)


def check_schema(value, schema, root=None):
    root = root or schema

    def fail():
        raise Fail("INVALID_SCHEMA_SHAPE")

    def visit(v, rule, depth):
        if depth > 64:
            raise Fail("SCHEMA_DEPTH_EXCEEDED")
        if "$ref" in rule:
            demand(rule["$ref"].startswith("#/$defs/"), "EXTERNAL_SCHEMA_REF_FORBIDDEN")
            return visit(v, root["$defs"][rule["$ref"][len("#/$defs/"):]], depth + 1)
        if "anyOf" in rule:
            for alternative in rule["anyOf"]:
                try:
                    visit(v, alternative, depth + 1)
                    return None
                except Fail:
                    continue
            fail()
        if "const" in rule and not same(v, rule["const"]):
            fail()
        if "enum" in rule and not any(same(v, option) for option in rule["enum"]):
            fail()
        kind = rule.get("type")
        if kind == "null" and v is not None:
            fail()
        if kind == "object":
            if not isinstance(v, dict) or any(k not in v for k in rule.get("required", [])):
                fail()
            properties = rule.get("properties", {})
            for key, child in v.items():
                if key in properties:
                    visit(child, properties[key], depth + 1)
                elif rule.get("additionalProperties") is False:
                    fail()
                elif isinstance(rule.get("additionalProperties"), dict):
                    visit(child, rule["additionalProperties"], depth + 1)
        if kind == "array":
            if not isinstance(v, list) or len(v) < rule.get("minItems", 0) or len(v) > rule.get("maxItems", 100000):
                fail()
            if rule.get("uniqueItems") and len({canonical(item) for item in v}) != len(v):
                fail()
            for item in v:
                visit(item, rule.get("items", {}), depth + 1)
        if kind == "string":
            if not isinstance(v, str) or len(v) < rule.get("minLength", 0) or len(v) > rule.get("maxLength", 20000000):
                fail()
            if "pattern" in rule and not _pattern(rule["pattern"]).search(v):
                fail()
        if kind == "integer" and not is_integer(v, rule.get("minimum"), rule.get("maximum")):
            fail()
        if kind == "boolean" and not isinstance(v, bool):
            fail()
        return None

    canonical(value)
    visit(value, schema, 0)


def partial_schema(schema):
    """The record schema with the members the native issuer may conceal made optional (conformity-record.md,
    "SD-JWT encoding"): actor and party names and identifiers, criteria and decision notes."""
    relaxed = json.loads(json.dumps(schema))
    actor = relaxed["$defs"]["actor"]
    actor["required"] = [k for k in actor["required"] if k not in ("name", "identifiers")]
    parties = relaxed["properties"]["specification"]["properties"]["parties"]["items"]
    parties["required"] = [k for k in parties["required"] if k not in ("name", "identifiers")]
    relaxed["properties"]["specification"]["properties"]["criteria"]["minItems"] = 0
    decisions = relaxed["properties"]["decisions"]["items"]
    decisions["required"] = [k for k in decisions["required"] if k != "note"]
    return relaxed


PARTIAL_SCHEMAS = {k: partial_schema(v) for k, v in SCHEMAS.items() if k in (RECORD_10,) + SUPPLEMENTED}

# ---------- record semantics ----------
_NAMESPACE = re.compile(r"[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*){2,}\Z", re.ASCII)
_URI = re.compile(r"[a-z][a-z0-9+.-]*:", re.ASCII)
_PROFILE = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z", re.ASCII)
_REF = re.compile(r"sha256:[a-f0-9]{64}\Z", re.ASCII)
_DURATION = re.compile(r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d{1,3})?)S)?)?\Z", re.ASCII)
TERMS = {"SA": "FIRST_PARTY", "BD": "SECOND_PARTY", "MV": "THIRD_PARTY", "TI": "THIRD_PARTY", "BE": "SECOND_PARTY", "BR": "SECOND_PARTY"}
OUTCOMES = {"MET": "CONFORM", "NEEDS_CHANGES": "NONCONFORM", "NOT_MET": "NONCONFORM", "UNDETERMINED": "INDETERMINATE"}
NEXT_STATE = {"ACCEPT": "CONFORM", "REJECT": "NONCONFORM", "REQUEST_CHANGES": "CHANGES_REQUESTED", "REQUEST_EVIDENCE": "AWAITING_EVIDENCE"}
_GRANDFATHERED = frozenset(("art-lojban cel-gaulish en-gb-oed i-ami i-bnn i-default i-enochian i-hak i-klingon i-lux i-mingo "
                            "i-navajo i-pwn i-tao i-tay i-tsu no-bok no-nyn sgn-be-fr sgn-be-nl sgn-ch-de zh-guoyu zh-hakka "
                            "zh-min zh-min-nan zh-xiang").split())


def language_tag(tag):
    """RFC 5646 well-formed (no registry), rejecting repeated variants and repeated extension singletons."""
    if not isinstance(tag, str) or not 0 < len(tag) <= 255 or not tag.isascii():
        return False
    lower = tag.lower()
    if lower in _GRANDFATHERED:
        return True
    parts, i = lower.split("-"), 0
    full = lambda p, s: re.fullmatch(p, s, re.ASCII) is not None  # noqa: E731
    at = lambda j: parts[j] if j < len(parts) else ""  # noqa: E731
    if parts[0] == "x":
        return len(parts) > 1 and all(full(r"[a-z0-9]{1,8}", p) for p in parts[1:])
    if not full(r"[a-z]{2,8}", parts[0]):
        return False
    i = 1
    if len(parts[0]) <= 3:
        for _ in range(3):
            if full(r"[a-z]{3}", at(i)):
                i += 1
            else:
                break
    if full(r"[a-z]{4}", at(i)):
        i += 1
    if full(r"[a-z]{2}|[0-9]{3}", at(i)):
        i += 1
    variants = set()
    while full(r"[a-z0-9]{5,8}|[0-9][a-z0-9]{3}", at(i)):
        if at(i) in variants:
            return False
        variants.add(at(i))
        i += 1
    singletons = set()
    while full(r"[0-9a-wy-z]", at(i)):
        if at(i) in singletons:
            return False
        singletons.add(at(i))
        i += 1
        start = i
        while full(r"[a-z0-9]{2,8}", at(i)):
            i += 1
        if i == start:
            return False
    if at(i) == "x":
        i += 1
        start = i
        while full(r"[a-z0-9]{1,8}", at(i)):
            i += 1
        if i == start:
            return False
    return i == len(parts)


def duration_ok(text):
    match = _DURATION.match(text) if isinstance(text, str) else None
    return bool(match) and any(g is not None for g in match.groups()) and not text.endswith("T")


def check_extensions(slot, handlers):
    demand(isinstance(slot, dict) and isinstance(slot.get("extensions"), dict) and isinstance(slot.get("critical"), list), "INVALID_EXTENSION_SLOT")
    demand(len(set(slot["critical"])) == len(slot["critical"]), "DUPLICATE_CRITICAL_EXTENSION")
    demand(all(_NAMESPACE.match(k) for k in slot["extensions"]), "INVALID_EXTENSION_NAMESPACE")
    demand("org.humanjudgment.party-signature" not in slot["extensions"], "PARTY_HELD_SIGNATURE_NOT_IMPLEMENTED")
    for name in slot["critical"]:
        demand(name in slot["extensions"] and name in handlers, "UNSUPPORTED_CRITICAL_EXTENSION")


def specification_digest(spec):
    body = {k: v for k, v in spec.items() if k != "reference"}
    body["reference"] = {k: v for k, v in spec["reference"].items() if k != "digest"}
    return json_digest(body)


def object_digest(obj):
    body = {k: v for k, v in obj.items() if k not in ("reference", "eventDigest")}
    body["reference"] = {k: v for k, v in obj["reference"].items() if k != "digest"}
    return json_digest(body)


def check_limitations(record):
    codes = record.get("limitations", [])
    demand(isinstance(codes, list) and len(codes) <= 1000 and len(set(map(str, codes))) == len(codes)
           and all(isinstance(c, str) and c in LIMITATION_CATALOGS[record["schema"]] for c in codes), "INVALID_RECORD_LIMITATIONS")
    return list(codes)


def check_reporters(record):
    """The distinct reporter origins a record names, ascending by UTF-16 code units (conformity-verification-1.3.md).
    Each is an HTTPS origin other than the issuer, and the record declares the reporter limitation exactly when it names one.
    Only a Record 1.3 can carry the member; for earlier versions the result is empty."""
    reporters = []
    for row in record["agreements"] + record["deliveries"] + record["decisions"]:
        attribution = row["actor"].get("attribution") if isinstance(row.get("actor"), dict) else None
        if attribution is None:
            continue
        try:
            issuer_did(attribution["reporter"])
        except Fail:
            raise Fail("INVALID_ACTOR_ATTRIBUTION")
        demand(attribution["reporter"] != record["identity"]["issuer"], "INVALID_ACTOR_ATTRIBUTION")
        if attribution["reporter"] not in reporters:
            reporters.append(attribution["reporter"])
    demand((REPORTER_LIMITATION in record.get("limitations", [])) == bool(reporters), "INVALID_ACTOR_ATTRIBUTION")
    return sorted(reporters, key=lambda origin: origin.encode("utf-16-be"))


def validate_record(record, handlers):
    """Structure, digests and the one closure machine (conformity-record.md). Returns the derived state."""
    check_schema(record, SCHEMAS[record["schema"]])
    check_limitations(record)
    check_reporters(record)
    demand(_URI.match(record["identity"]["resultId"]) is not None, "INVALID_RECORD_IDENTITY")
    issuer_did(record["identity"]["issuer"])
    demand(_PROFILE.match(record["profile"]) is not None or _URI.match(record["profile"]) is not None, "INVALID_PROFILE")
    issued_at = record["issuance"]["issuedAt"]
    require_time(issued_at)
    check_extensions(record, handlers)
    spec = record["specification"]
    check_extensions(spec, handlers)
    commitments = record["commitments"]
    committed = [commitments["tsto"]] + commitments["jepEvents"] + [commitments["attachmentManifest"]]
    demand(len({c["path"] for c in committed}) == len(committed) and all(safe_path(c["path"]) and c["mediaType"] and _REF.match(c["sha256"]) for c in committed), "INVALID_EVIDENCE_COMMITMENT")
    ref = spec["reference"]
    demand(isinstance(ref.get("id"), str) and ref["id"] and is_integer(ref.get("version"), 1) and _REF.match(ref["digest"]), "INVALID_REFERENCE")
    demand(ref["digest"] == specification_digest(spec), "SPECIFICATION_DIGEST_MISMATCH")
    terms = spec["acceptanceTerms"]
    code = terms["terms"][len(ACCEPTERMS) + 1:]
    demand(terms["terms"] == ACCEPTERMS + "#" + code and code in TERMS, "INVALID_ACCEPTANCE_TERMS")
    demand(duration_ok(terms["judgmentWindow"]) and duration_ok(terms["defectNotificationPeriod"]), "INVALID_ELAPSED_DURATION")
    demand(spec["textLanguage"] is None or language_tag(spec["textLanguage"]), "INVALID_LANGUAGE_TAG")
    demand(0 < len(spec["criteria"]) <= 1000, "INVALID_CRITERIA")
    criteria = {}
    for c in spec["criteria"]:
        demand(c["id"] and c["id"] not in criteria and all(isinstance(c[k], str) for k in ("title", "requirement", "evidenceRequired")), "INVALID_CRITERIA")
        demand(c["determinability"] in ("MACHINE", "MEASURED", "HUMAN"), "INVALID_DETERMINABILITY")
        check_extensions(c, handlers)
        criteria[c["id"]] = c
    parties = {}
    for p in spec["parties"]:
        demand(p["id"] and p["id"] not in parties and p["role"] in ("FIRST_PARTY", "SECOND_PARTY", "THIRD_PARTY"), "INVALID_PARTY")
        demand(all(_URI.match(i["scheme"]) and i["value"] for i in p["identifiers"]), "INVALID_PARTY_IDENTIFIER")
        check_extensions(p, handlers)
        parties[p["id"]] = p["role"]
    demand("FIRST_PARTY" in parties.values() and "SECOND_PARTY" in parties.values(), "REQUIRED_PARTIES_MISSING")

    def check_actor(actor, party, at, scope):
        demand(actor["id"] and parties.get(actor["partyId"]) == party, "ACTOR_PARTY_MISMATCH")
        check_extensions(actor, handlers)
        demand(all(_URI.match(i["scheme"]) and i["value"] for i in actor["identifiers"]), "INVALID_PARTY_IDENTIFIER")
        grant = actor["delegation"]
        if grant is not None:
            require_time(grant["validFrom"])
            require_time(grant["validUntil"])
            demand(grant["principal"] and grant["id"] and grant["scope"] == scope and grant["validFrom"] <= at < grant["validUntil"], "INVALID_DELEGATION")

    objects = {}

    def add(object_id, kind, at, event_digest):
        require_time(at)
        demand(object_id and object_id not in objects and _REF.match(event_digest) and at <= issued_at, "INVALID_OBJECT_EVENT")
        objects[object_id] = (kind, at, event_digest)

    for a in record["agreements"]:
        demand(a["specificationDigest"] == ref["digest"] and a["party"] in ("FIRST_PARTY", "SECOND_PARTY"), "AGREEMENT_BINDING_INVALID")
        check_actor(a["actor"], a["party"], a["recordedAt"], "AGREE")
        add(a["id"], "AGREEMENT", a["recordedAt"], a["eventDigest"])
    deliveries = {}
    for index, d in enumerate(record["deliveries"]):
        demand(d["reference"]["id"] not in deliveries, "DUPLICATE_DELIVERY")
        deliveries[d["reference"]["id"]] = d
    for index, d in enumerate(record["deliveries"]):
        check_extensions(d, handlers)
        previous = record["deliveries"][index - 1]["reference"]["id"] if index else None
        demand(d["specificationDigest"] == ref["digest"] and d["reference"]["version"] == index + 1 and _REF.match(d["manifestDigest"])
               and d["previousDeliveryId"] == previous, "DELIVERY_BINDING_INVALID")
        check_actor(d["actor"], "FIRST_PARTY", d["recordedAt"], "DELIVER")
        demand(d["reference"]["digest"] == object_digest(d), "DELIVERY_DIGEST_MISMATCH")
        add(d["reference"]["id"], "DELIVERY", d["recordedAt"], d["eventDigest"])
    decisions = {}
    for d in record["decisions"]:
        demand(d["reference"]["id"] not in decisions, "DUPLICATE_DECISION")
        decisions[d["reference"]["id"]] = d
    for index, d in enumerate(record["decisions"]):
        check_extensions(d, handlers)
        delivery = deliveries.get(d["deliveryId"])
        demand(delivery is not None and d["specificationDigest"] == ref["digest"] and d["reference"]["version"] == index + 1
               and d["manifestDigest"] == delivery["manifestDigest"] and d["recordedAt"] >= delivery["recordedAt"], "DECISION_BINDING_INVALID")
        demand(d["verb"] == "J" or (d["verb"] == "V" and d["judgeParty"] == "THIRD_PARTY"), "PARTY_VERIFICATION_FORBIDDEN")
        evaluation = d.get("purpose") == "EVALUATION"
        if evaluation:
            demand(d["verb"] == "V" and d["judgeParty"] == "THIRD_PARTY" and d["action"] == "EVALUATE", "EVALUATION_PARTY_OR_ACTION_INVALID")
        else:
            demand(d["judgeParty"] == TERMS[code], "TERMS_JUDGE_MISMATCH")
        check_actor(d["actor"], d["judgeParty"], d["recordedAt"], "VERIFY" if evaluation else "JUDGE")
        ids = [c["criterionId"] for c in d["criteria"]]
        if evaluation:
            demand(ids and len(set(ids)) == len(ids), "EXACT_AGREED_CRITERIA_REQUIRED")
        else:
            demand(len(ids) == len(criteria) and len(set(ids)) == len(criteria), "EXACT_AGREED_CRITERIA_REQUIRED")
        for c in d["criteria"]:
            demand(c["criterionId"] in criteria and c["outcome"] == OUTCOMES.get(c["verdict"]), "CRITERION_OUTCOME_MISMATCH")
            if evaluation:
                demand(criteria[c["criterionId"]]["determinability"] != "HUMAN", "EVALUATION_REQUIRES_DETERMINABLE_CRITERIA")
            if code == "MV":
                demand(criteria[c["criterionId"]]["determinability"] != "HUMAN", "TERMS_DETERMINABILITY_MISMATCH")
        demand(evaluation or d["action"] in NEXT_STATE, "INVALID_DECISION_ACTION")
        verdicts = [c["verdict"] for c in d["criteria"]]
        # "An ACCEPT decision requires all MET verdicts" (code registered by the 1.2 catalog).
        if d["action"] == "ACCEPT":
            demand(all(v == "MET" for v in verdicts), "ACCEPTANCE_NOT_CONFORM")
        if d["action"] == "REQUEST_CHANGES":
            demand(any(v in ("NEEDS_CHANGES", "NOT_MET") for v in verdicts), "CHANGE_REASON_MISSING")
        if d["action"] == "REQUEST_EVIDENCE":
            demand("UNDETERMINED" in verdicts, "EVIDENCE_REASON_MISSING")
        if d["action"] == "REJECT":
            demand("NOT_MET" in verdicts, "REJECTION_REASON_MISSING")
        demand(d["reference"]["digest"] == object_digest(d), "DECISION_DIGEST_MISMATCH")
        add(d["reference"]["id"], "EVALUATION" if evaluation else "DECISION", d["recordedAt"], d["eventDigest"])

    state, delivery_id, decision_id, previous, last_at = "OPEN", None, None, None, ""
    seen, agreed, seen_objects = set(), set(), set()
    for e in record["history"]:
        require_time(e["recordedAt"])
        demand(e["id"] not in seen and e["eventDigest"] not in seen and e["recordedAt"] >= last_at and e["recordedAt"] <= issued_at
               and _REF.match(e["eventDigest"]) and e["previousDigest"] == previous, "HISTORY_CHAIN_INVALID")
        if e["kind"] not in KNOWN_KINDS:
            # Unknown unnamespaced events are errors; unknown namespaced events poison interpretation.
            demand(_URI.match(e["kind"]) is not None, "UNKNOWN_UNNAMESPACED_EVENT")
            state = "INDETERMINATE"
        else:
            obj = objects.get(e["objectId"])
            demand(obj is not None and obj == (e["kind"], e["recordedAt"], e["eventDigest"]) and e["objectId"] not in seen_objects, "HISTORY_OBJECT_MISMATCH")
            seen_objects.add(e["objectId"])
            if state != "INDETERMINATE":
                if e["kind"] == "AGREEMENT":
                    party = next(a["party"] for a in record["agreements"] if a["id"] == e["objectId"])
                    demand(state == "OPEN" and party not in agreed, "AGREEMENT_SEQUENCE_INVALID")
                    agreed.add(party)
                    if len(agreed) == 2:
                        state = "AGREED"
                elif e["kind"] == "DELIVERY":
                    demand(state in ("AGREED", "SUBMITTED", "CHANGES_REQUESTED", "AWAITING_EVIDENCE"), "DELIVERY_SEQUENCE_INVALID")
                    demand(deliveries[e["objectId"]]["respondsToDecisionId"] == decision_id, "DELIVERY_RESPONSE_MISMATCH")
                    delivery_id, state = e["objectId"], "SUBMITTED"
                elif e["kind"] == "EVALUATION":
                    demand(state == "SUBMITTED" and decisions[e["objectId"]]["deliveryId"] == delivery_id, "EVALUATION_SEQUENCE_INVALID")
                else:
                    d = decisions[e["objectId"]]
                    demand(state == "SUBMITTED" and d["deliveryId"] == delivery_id, "DECISION_SEQUENCE_INVALID")
                    decision_id, state = e["objectId"], NEXT_STATE[d["action"]]
        seen.add(e["id"])
        seen.add(e["eventDigest"])
        last_at, previous = e["recordedAt"], e["eventDigest"]
    demand(len(seen_objects) == len(objects), "HISTORY_COVERAGE_INCOMPLETE")
    current = record["current"]
    demand(current["state"] == state and current["deliveryId"] == delivery_id and current["decisionId"] == decision_id, "CURRENT_STATE_MISMATCH")
    return state, state == "CONFORM" and len(agreed) == 2


def critical_manifest(value, path=""):
    """Every nonempty `critical` list with its JSON Pointer, in document order with members in canonical order."""
    found = []
    if isinstance(value, dict):
        if isinstance(value.get("critical"), list) and value["critical"]:
            found.append({"path": path or "/", "keys": list(value["critical"])})
        for key in sorted(value, key=lambda k: k.encode("utf-16-be", "surrogatepass")):
            found.extend(critical_manifest(value[key], path + "/" + key.replace("~", "~0").replace("/", "~1")))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(critical_manifest(item, "%s/%d" % (path, index)))
    return found


def verify_record_jwt(presentation, keys, full, handlers):
    """Authenticate the issuer-signed JWT, resolve disclosures and validate the visible or complete Record."""
    parts = presentation.split("~")
    jwt, disclosures = parts[0], parts[1:]
    demand(len(parts) >= 2 and disclosures[-1] == "" and all(disclosures[:-1]), "INVALID_SD_JWT")
    disclosures = disclosures[:-1]
    header, payload = verify_compact_jwt(jwt, keys)
    demand(header.get("typ") == "sd-jwt", "UNSUPPORTED_SD_JWT_TYPE")
    demand(payload.get("_sd_alg") == "sha-256", "UNSUPPORTED_SD_ALGORITHM")
    value, disclosed, total, missing = resolve_disclosures(payload, disclosures)
    demand(not (full and missing), "INCOMPLETE_DISCLOSURE_SET")
    identity = value.get("identity") if isinstance(value.get("identity"), dict) else {}
    demand(value.get("iss") == identity.get("issuer"), "ISSUER_IDENTIFIER_MISMATCH")
    issuance = value.get("issuance") if isinstance(value.get("issuance"), dict) else {}
    issued_ms = epoch_ms(issuance.get("issuedAt"))
    demand(value.get("schema") in (RECORD_10,) + SUPPLEMENTED and issued_ms is not None and value["iat"] == issued_ms / 1000
           and not isinstance(value.get("disclosureCount"), bool) and value.get("disclosureCount") == total, "RECORD_ENVELOPE_MISMATCH")
    manifest = value.get("criticalManifest")
    demand(isinstance(manifest, list) and all(isinstance(m, dict) and isinstance(m.get("path"), str) and isinstance(m.get("keys"), list) for m in manifest), "CRITICAL_MANIFEST_INVALID")
    for item in manifest:
        for name in item["keys"]:
            demand(isinstance(name, str) and name in handlers, "UNSUPPORTED_CRITICAL_EXTENSION")
    record = {k: v for k, v in value.items() if k not in ("iss", "iat", "disclosureCount", "criticalManifest")}
    check_schema(record, PARTIAL_SCHEMAS[record["schema"]])
    require_time(record["issuance"]["issuedAt"])
    for row in record["agreements"] + record["deliveries"] + record["decisions"] + record["history"]:
        require_time(row["recordedAt"])
    if missing:
        return record, disclosed, total, "NOT_ESTABLISHED"
    demand(same(critical_manifest(record), manifest), "CRITICAL_MANIFEST_INVALID")
    _state, complete = validate_record(record, handlers)
    return record, disclosed, total, "COMPLETE" if complete else "NOT_COMPLETE"


# ---------- origin evidence: TSTO/00 and JEP Core 0.7 events under Binding/02 ----------
def _text(value):
    return isinstance(value, str) and len(value) > 0


def _exact(value, required, optional=()):
    return isinstance(value, dict) and all(k in value for k in required) and all(k in required or k in optional for k in value)


_ABS_URI = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:\S*\Z", re.ASCII)
_TSTO_DIGEST = re.compile(r"sha-256:[A-Za-z0-9_-]{43}\Z", re.ASCII)
_INSTANT = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-](\d{2}):(\d{2}))\Z", re.ASCII | re.IGNORECASE)


def _uri(value):
    return _text(value) and _ABS_URI.match(value) is not None


def _immutable(value):
    return _exact(value, ("id", "digest")) and _uri(value["id"]) and isinstance(value["digest"], str) and _TSTO_DIGEST.match(value["digest"]) is not None


def _instant_ok(value):
    match = _INSTANT.match(value) if isinstance(value, str) else None
    if not match:
        return False
    try:
        datetime(int(match.group(1)), int(match.group(2)), int(match.group(3)))
    except ValueError:
        return False
    return int(match.group(4)) < 24 and int(match.group(5)) < 60 and int(match.group(6)) < 60 \
        and int(match.group(7) or 0) < 24 and int(match.group(8) or 0) < 60


def _evidence_ref(value):
    return _exact(value, ("id", "kind", "digest", "observed_at"), ("media_type", "location")) and _uri(value["id"]) \
        and _text(value["kind"]) and isinstance(value["digest"], str) and _TSTO_DIGEST.match(value["digest"]) is not None \
        and _instant_ok(value["observed_at"]) and ("media_type" not in value or _text(value["media_type"])) \
        and ("location" not in value or _uri(value["location"]))


def binding_reference(event):
    """The TSTO reference of a JEP Core 0.7 event carrying the Binding/02 marker, or None (BINDING_02.md)."""
    ascii_id = lambda v: _text(v) and v.isascii()  # noqa: E731
    if not _exact(event, ("jep", "id", "verb", "who", "when", "what", "ref", "ext"), ("aud", "ext_crit", "sig")):
        return None
    if event["jep"] != "1" or not ascii_id(event["id"]) or not _text(event["who"]) or not is_integer(event["when"]) \
            or not isinstance(event["what"], dict) or not isinstance(event["ext"], dict) \
            or any(not k or not isinstance(v, dict) for k, v in event["ext"].items()):
        return None
    if "aud" in event and not _text(event["aud"]):
        return None
    if "ext_crit" in event and event["ext_crit"] != []:
        return None
    marker = event["ext"].get("jep-tsto.binding")
    if not _exact(marker, ("version", "spec")) or marker["version"] != "02" or marker["spec"] != "JEP-TSTO-Binding/02" \
            or "prooftask.binding" in event["ext"]:
        return None
    what = event["what"]
    if "reason" in what and not isinstance(what["reason"], str):
        return None
    if event["verb"] == "T":
        ref = event["ref"]
        if what.get("claim") != "tsto_termination" or not _text(what.get("termination_scope")) or "target" in what \
                or not _exact(ref, ("type", "value"), ("hash",)) or ref["type"] != "jep:event" \
                or not _exact(ref["value"], ("who", "id")) or not _text(ref["value"]["who"]) or not ascii_id(ref["value"]["id"]) \
                or ("hash" in ref and not (isinstance(ref["hash"], str) and _REF.match(ref["hash"]))):
            return None
        target = what.get("subject")
    else:
        if not _exact(event["ref"], ("type", "value")) or event["ref"]["type"] != "tsto:target-state-transition":
            return None
        target = event["ref"]["value"]
        verb = event["verb"]
        if verb == "J":
            if what.get("claim") != "tsto_judgment" or what.get("decision") not in ("propose", "accept", "reject", "reassess") \
                    or ("context" in what and not isinstance(what["context"], dict)):
                return None
        elif verb == "D":
            if what.get("claim") != "tsto_delegation" or not _text(what.get("delegatee")) or "scope" not in what:
                return None
        elif verb == "V":
            scope, evidence = what.get("verification_scope"), what.get("evidence")
            if what.get("claim") != "tsto_verification" or not isinstance(scope, list) or not scope or not all(_text(s) for s in scope) \
                    or len(set(scope)) != len(scope) or what.get("result") not in ("SATISFIED", "NOT_SATISFIED", "INDETERMINATE") \
                    or not _immutable(what.get("policy_ref")) or not isinstance(evidence, list) or not evidence \
                    or not all(_evidence_ref(x) for x in evidence) or ("observed_at" in what and not _instant_ok(what["observed_at"])):
                return None
        else:
            return None
    if not (_exact(target, ("kind", "type", "spec", "id", "digest")) and target["kind"] == "external_object"
            and target["type"] == "TargetStateTransition" and target["spec"] == "TSTO/00" and _uri(target["id"])
            and isinstance(target["digest"], str) and _TSTO_DIGEST.match(target["digest"])):
        return None
    return target


def _references_tsto(event, tsto):
    target = binding_reference(event)
    return target is not None and same(target, {"kind": "external_object", "type": "TargetStateTransition", "spec": "TSTO/00",
                                                 "id": tsto["id"], "digest": tsto["integrity"]["value"]})


def verify_origin(record, tsto, events, keys):
    """TSTO and JEP evidence of a full Package (conformity-record.md "Visible evidence", conformity-package.md)."""
    spec = record["specification"]
    integrity = tsto.get("integrity") if isinstance(tsto, dict) else None
    demand(isinstance(tsto, dict) and tsto.get("spec") == "TSTO/00" and tsto.get("type") == "TargetStateTransition"
           and isinstance(tsto.get("id"), str) and isinstance(integrity, dict) and integrity.get("alg") == "sha-256"
           and integrity.get("canonicalization") == "RFC8785", "TSTO_ORIGIN_EVIDENCE_INVALID")
    material = {k: v for k, v in tsto.items() if k != "integrity"}
    parameters = (tsto.get("verification") or {}).get("parameters") if isinstance(tsto.get("verification"), dict) else None
    demand(integrity.get("value") == "sha-256:" + b64url(hashlib.sha256(canonical_bytes(material)).digest())
           and isinstance(parameters, dict) and parameters.get("org.humanjudgment.specification-digest") == spec["reference"]["digest"],
           "TSTO_SPECIFICATION_BINDING_MISMATCH")
    demand(isinstance(tsto.get("subject"), dict) and tsto["subject"].get("id") == record["identity"]["resultId"], "TSTO_SUBJECT_BINDING_MISMATCH")
    claims = [{"op": "eq", "path": "/criteria/" + c["id"].replace("~", "~0").replace("/", "~1"), "value": c} for c in spec["criteria"]]
    demand(isinstance(tsto.get("profile"), dict) and tsto["profile"].get("id") == NATIVE_TSTO_PROFILE
           and isinstance(tsto.get("target"), dict) and same(tsto["target"].get("claims"), claims), "TSTO_TARGET_BINDING_MISMATCH")
    by_digest = {}
    for event in events:
        by_digest[json_digest(event)] = event
    demand(len(by_digest) == len(events), "JEP_ORIGIN_EVIDENCE_INVALID")
    accounted = {}
    decisions = {d["reference"]["id"]: d for d in record["decisions"]}
    deliveries = {d["reference"]["id"]: d for d in record["deliveries"]}
    agreements = {a["id"]: a for a in record["agreements"]}
    for h in record["history"]:
        event = by_digest.get(h["eventDigest"])
        demand(event is not None and _references_tsto(event, tsto), "JEP_ORIGIN_EVIDENCE_INVALID")
        obj = agreements.get(h["objectId"]) or deliveries.get(h["objectId"]) or decisions.get(h["objectId"])
        binding = event["ext"].get("org.humanjudgment.record-binding")
        demand(isinstance(binding, dict) and binding.get("objectId") == h["objectId"]
               and binding.get("specificationDigest") == spec["reference"]["digest"] and event["id"] == h["id"]
               and event["when"] == epoch_ms(h["recordedAt"]) // 1000 and (obj is None or event["who"] == obj["actor"]["id"]),
               "JEP_ORIGIN_EVIDENCE_INVALID")
        decision, delivery, agreement = decisions.get(h["objectId"]), deliveries.get(h["objectId"]), agreements.get(h["objectId"])
        expected = (decision or delivery or {}).get("reference", {}).get("digest") or spec["reference"]["digest"]
        demand(binding.get("objectDigest") == expected, "JEP_RECORD_BINDING_MISMATCH")
        what = event["what"]
        if decision is not None:
            demand(event["verb"] == decision["verb"], "JEP_JUDGMENT_KIND_MISMATCH")
            if decision["verb"] == "J":
                demand(what.get("decision") == {"ACCEPT": "accept", "REJECT": "reject", "REQUEST_CHANGES": "reassess",
                                                "REQUEST_EVIDENCE": "reassess"}.get(decision["action"]), "JEP_JUDGMENT_KIND_MISMATCH")
            else:
                outcomes = [c["outcome"] for c in decision["criteria"]]
                result = "NOT_SATISFIED" if "NONCONFORM" in outcomes else "SATISFIED" if all(o == "CONFORM" for o in outcomes) else "INDETERMINATE"
                demand(what.get("result") == result and same(what.get("policy_ref"), tsto["verification"].get("policy")), "JEP_VERIFICATION_BINDING_MISMATCH")
        elif h["kind"] in ("AGREEMENT", "DELIVERY"):
            demand(event["verb"] == "J", "JEP_JUDGMENT_KIND_MISMATCH")
        if agreement is not None:
            demand(what.get("decision") == ("propose" if agreement["party"] == "SECOND_PARTY" else "accept"), "JEP_JUDGMENT_KIND_MISMATCH")
        if delivery is not None:
            demand(what.get("decision") == "propose", "JEP_JUDGMENT_KIND_MISMATCH")
        accounted[h["eventDigest"]] = h["recordedAt"]
    auxiliary = 0
    if "limitations" in record:
        # Package supplement 1.1: a neutral reader authenticates unbound supplementary events without interpreting them.
        for digest, event in by_digest.items():
            if digest not in accounted and isinstance(event, dict) and isinstance(event.get("ext"), dict) \
                    and "org.humanjudgment.record-binding" not in event["ext"] and is_integer(event.get("when")):
                accounted[digest] = time_of_ms(int(event["when"]) * 1000)
                auxiliary += 1
    demand(len(accounted) == len(events), "JEP_ORIGIN_EVIDENCE_INVALID")
    identifiers = set()
    for digest, recorded_at in accounted.items():
        require_time(recorded_at)
        demand(recorded_at <= record["issuance"]["issuedAt"], "JEP_ORIGIN_EVIDENCE_INVALID")
        event = by_digest[digest]
        demand(_references_tsto(event, tsto) and isinstance(event["id"], str) and event["id"] not in identifiers
               and _text(event["who"]) and event["when"] == epoch_ms(recorded_at) // 1000, "JEP_ORIGIN_EVIDENCE_INVALID")
        identifiers.add(event["id"])
        sig = event.get("sig")
        pieces = sig.split(".") if isinstance(sig, str) else []
        demand(len(pieces) == 3 and pieces[1] == "", "JEP_SIGNATURE_INVALID")
        try:
            header_bytes = b64url_decode(pieces[0])
            demand(len(header_bytes) <= 4096, "JEP_SIGNATURE_INVALID")
            header = parse_bytes(header_bytes)
            signature = b64url_decode(pieces[2])
        except (Fail, InputError):
            raise Fail("JEP_SIGNATURE_INVALID")
        demand(isinstance(header, dict) and header.get("alg") == "Ed25519" and isinstance(header.get("kid"), str)
               and header.get("typ", "JEP") == "JEP" and set(header) <= {"alg", "kid", "typ"}, "JEP_SIGNATURE_INVALID")
        unsigned = {k: v for k, v in event.items() if k != "sig"}
        demand(len(signature) == 64, "JEP_SIGNATURE_INVALID")
        public_key = keys.key(record["identity"]["issuer"], header["kid"], recorded_at)
        signing_input = (pieces[0] + "." + b64url(canonical_bytes(unsigned))).encode("ascii")
        demand(_ed25519.verify(public_key, signing_input, signature), "JEP_SIGNATURE_INVALID")
    return auxiliary


# ---------- Package ----------
def safe_path(path):
    return isinstance(path, str) and 0 < len(path) < 1024 and not path.startswith("/") and "\\" not in path \
        and all(part not in ("", ".", "..") for part in path.split("/"))


def _file_bytes(entry):
    demand(isinstance(entry, dict) and entry.get("encoding") == "base64url" and isinstance(entry.get("data"), str), "PACKAGE_CONTENT_MISMATCH")
    return b64url_decode(entry["data"], allow_empty=True)


def _leaks(value, depth=0):
    """TSTO or JEP event content anywhere, including inside JSON-looking strings (partial presentations)."""
    if depth > 64:
        return True
    if isinstance(value, str) and re.match(r"\s*[\[{\"]", value):
        try:
            return _leaks(parse_text(value), depth + 1)
        except InputError:
            return True
    if isinstance(value, dict):
        if value.get("spec") == "TSTO/00" or (value.get("jep") == "1" and "who" in value):
            return True
        return any(_leaks(v, depth + 1) for v in value.values())
    if isinstance(value, list):
        return any(_leaks(v, depth + 1) for v in value)
    return False


def reporter_statements(record, files):
    """Record 1.3 package supplement (conformity-record-1.3.md, "Reporter statements in a Package"). A statement under
    reports/ is accepted when it names an object whose actor the record attributes to the same reporter and its Ed25519
    signature over the canonical JSON of `statement` verifies under the key it carries. It never changes the verdict."""
    if record["schema"] != RECORD_13:
        return []
    attributed = {}

    def add(object_id, actor):
        if isinstance(actor, dict) and "attribution" in actor:
            digests = {i.get("value") for i in actor.get("identifiers", []) if isinstance(i, dict) and i.get("scheme") == REPORTER_STATEMENT_SCHEME}
            attributed[object_id] = (actor["attribution"]["reporter"], digests)
    for o in record["agreements"]:
        add(o["id"], o.get("actor"))
    for o in record["deliveries"] + record["decisions"]:
        add(o["reference"]["id"], o.get("actor"))
    found = []
    for path in sorted((p for p in files if p.startswith("reports/")), key=lambda p: p.encode("utf-16-be")):
        try:
            entry = files[path]
            data = _file_bytes(entry)
            if entry.get("mediaType") != "application/json" or "sha256:" + sha256_hex(data) != entry.get("sha256"):
                continue
            v = parse_bytes(data)
            if not isinstance(v, dict) or sorted(v) != ["kid", "objectId", "publicKey", "reporter", "signature", "statement"]:
                continue
            target = attributed.get(v["objectId"]) if isinstance(v["objectId"], str) else None
            if target is None or target[0] != v["reporter"] or "sha256:" + sha256_hex(canonical_bytes(v["statement"])) not in target[1] \
                    or not isinstance(v["kid"], str) or not 0 < len(v["kid"]) <= 200 or not isinstance(v["publicKey"], str) \
                    or not isinstance(v["signature"], str) or not isinstance(v["statement"], dict):
                continue
            key, signature = b64url_decode(v["publicKey"]), b64url_decode(v["signature"])
            if len(key) != 32 or len(signature) != 64 or not _ed25519.verify(key, canonical_bytes(v["statement"]), signature):
                continue
            found.append({"path": path, "objectId": v["objectId"], "reporter": v["reporter"], "kid": v["kid"], "publicKey": v["publicKey"]})
        except (Fail, InputError, ValueError):
            continue
    return found


def verify_package(package, trust, handlers):
    demand(isinstance(package, dict) and set(package) == {"schema", "files"} and isinstance(package["files"], list)
           and len(package["files"]) <= 10000, "INVALID_PACKAGE")
    files = {}
    for entry in package["files"]:
        demand(isinstance(entry, dict) and safe_path(entry.get("path")) and entry["path"] not in files, "PACKAGE_CONTENT_MISMATCH")
        files[entry["path"]] = entry
    record_file = files.get("record.sd-jwt")
    demand(record_file is not None, "PACKAGE_CONTENT_MISMATCH")
    presentation = decode_utf8(_file_bytes(record_file))
    keys = KeyPolicy(trust, weigh_revoked=True)
    record, disclosed, total, closure = verify_record_jwt(presentation, keys, True, handlers)
    supplemented = record["schema"] in SUPPLEMENTED
    demand(supplemented or not keys.revoked_uses, "ISSUER_KEY_NOT_VALID_AT_ISSUANCE")
    accepted = {"record.sd-jwt"}

    def check(commitment):
        entry = files.get(commitment["path"])
        demand(entry is not None and entry.get("mediaType") == commitment["mediaType"] and entry.get("sha256") == commitment["sha256"]
               and "sha256:" + sha256_hex(_file_bytes(entry)) == commitment["sha256"], "PACKAGE_CONTENT_MISMATCH")
        accepted.add(commitment["path"])
        return _file_bytes(entry)

    demand(record_file.get("mediaType") == "application/sd-jwt" and "sha256:" + sha256_hex(_file_bytes(record_file)) == record_file.get("sha256"), "PACKAGE_CONTENT_MISMATCH")
    commitments = record["commitments"]
    tsto_bytes = check(commitments["tsto"])
    event_bytes = [check(c) for c in commitments["jepEvents"]]
    manifest = parse_bytes(check(commitments["attachmentManifest"]))
    demand(isinstance(manifest, list), "PACKAGE_CONTENT_MISMATCH")
    seen = set()
    for entry in manifest:
        demand(isinstance(entry, dict) and safe_path(entry.get("path")) and entry["path"].startswith("attachments/")
               and entry["path"] not in seen and isinstance(entry.get("mediaType"), str) and isinstance(entry.get("sha256"), str), "PACKAGE_CONTENT_MISMATCH")
        seen.add(entry["path"])
        check(entry)
    if supplemented and any(path.startswith("evidence/") for path in files):
        raise UnsupportedEvidence("This verifier does not implement anchoring evidence (evidence/, package standard 1.2).")
    statements = reporter_statements(record, files)
    accepted.update(s["path"] for s in statements)
    ignored = [path for path in files if path not in accepted]
    tsto, events = parse_bytes(tsto_bytes), [parse_bytes(b) for b in event_bytes]
    origin_keys = keys if supplemented else KeyPolicy(trust)
    auxiliary = verify_origin(record, tsto, events, origin_keys)
    status, key_reasons = revoked_decision(keys.revoked_uses + (origin_keys.revoked_uses if origin_keys is not keys else []))
    limitations = check_limitations(record)
    reporters = check_reporters(record)
    reasons = _unique(["ACTOR_ATTRIBUTION_RECORDER_ASSERTION"] + limitations)
    if any(h["kind"] not in KNOWN_KINDS for h in record["history"]):
        reasons.append("UNKNOWN_NAMESPACED_TRANSITION")
    if ignored:
        reasons.append("UNCOMMITTED_FILE")
    if auxiliary:
        reasons.append("JEP_AUXILIARY_NOT_INTERPRETED")
    report = {"schema": REPORTS[record["schema"]], "issuer": record["identity"]["issuer"], "status": status,
              "closure": closure, "disclosures": {"disclosed": disclosed, "total": total}}
    if "limitations" in record:
        report["limitations"] = limitations
    if reporters:
        report["reporters"] = reporters
    if statements:
        report["reporterStatements"] = [{k: s[k] for k in ("objectId", "reporter", "kid", "publicKey")} for s in statements]
    report.update({"reasons": reasons + key_reasons, "ignoredFiles": ignored, "commitments": commitments})
    return report


def verify_presentation(presentation, trust, handlers):
    keys = KeyPolicy(trust, weigh_revoked=True)
    record, disclosed, total, _closure = verify_record_jwt(presentation, keys, False, handlers)
    demand(not _leaks(record), "PARTIAL_PRESENTATION_LEAKS_COMMITTED_CONTENT")
    supplemented = record["schema"] in SUPPLEMENTED
    demand(supplemented or not keys.revoked_uses, "ISSUER_KEY_NOT_VALID_AT_ISSUANCE")
    status, key_reasons = revoked_decision(keys.revoked_uses)
    limitations = check_limitations(record)
    reporters = check_reporters(record)
    report = {"schema": REPORTS[record["schema"]], "issuer": record["identity"]["issuer"],
              "status": "INDETERMINATE" if status == "INDETERMINATE" else "PARTIAL_DISCLOSURE", "closure": "NOT_ESTABLISHED",
              "disclosures": {"disclosed": disclosed, "total": total}}
    if "limitations" in record:
        report["limitations"] = limitations
    if reporters:
        report["reporters"] = reporters
    report["reasons"] = _unique(["PARTIAL_DISCLOSURE", "JEP_ORIGIN_EVIDENCE_NOT_INCLUDED", "ACTOR_ATTRIBUTION_RECORDER_ASSERTION"] + limitations + key_reasons)
    report["commitments"] = record["commitments"]
    return report


# ---------- Status ----------
STATES = ("OPEN", "AGREED", "SUBMITTED", "CHANGES_REQUESTED", "AWAITING_EVIDENCE", "CONFORM", "NONCONFORM", "INDETERMINATE",
          "CONTESTED", "WITHDRAWN", "SUPERSEDED")


def verify_status(status, trust, expected, checked_at, handlers):
    check_schema(status, SCHEMAS[STATUS])
    issuer_did(status["identity"]["issuer"])
    demand(_URI.match(status["identity"]["resultId"]) is not None and status["state"] in STATES, "STATUS_SHAPE_INVALID")
    require_time(status["observedAt"])
    require_time(status["expiresAt"])
    lifetime = epoch_ms(status["expiresAt"]) - epoch_ms(status["observedAt"])
    demand(0 < lifetime <= 300000, "STATUS_VALIDITY_INVALID")
    check_extensions(status, handlers)
    require_time(checked_at)
    header, payload = verify_compact_jwt(status["signature"], KeyPolicy(trust))
    observation = {k: v for k, v in status.items() if k != "signature"}
    observation.update({"iss": status["identity"]["issuer"], "iat": epoch_ms(status["observedAt"]) / 1000})
    demand(header.get("typ") == "conformity-status+jwt" and same(payload, observation), "STATUS_SIGNATURE_BINDING_MISMATCH")
    demand(status["identity"]["issuer"] == expected.get("issuer"), "ISSUER_IDENTIFIER_MISMATCH")
    demand(status["identity"]["resultId"] == expected.get("resultId") and status["headDigest"] == expected.get("headDigest"), "STATUS_RECORD_BINDING_MISMATCH")
    fresh = status["observedAt"] <= checked_at < status["expiresAt"]
    reasons = ["ACTOR_ATTRIBUTION_RECORDER_ASSERTION"] + ([] if fresh else ["STATUS_NOT_YET_VALID" if checked_at < status["observedAt"] else "STATUS_EXPIRED"])
    return {"schema": REPORT_10, "issuer": status["identity"]["issuer"], "status": "VERIFIED_WITH_LIMITATIONS", "closure": "NOT_ESTABLISHED",
            "disclosures": {"disclosed": 0, "total": 0}, "reasons": reasons, "currentStatus": "FRESH" if fresh else "UNKNOWN",
            "currentState": status["state"] if fresh else None}


# ---------- Summary (VC 2.0, Data Integrity eddsa-jcs-2022) ----------
SUMMARY_CONTEXTS = ["https://www.w3.org/ns/credentials/v2", SUMMARY + "/context.jsonld"]
SUMMARY_BOUNDARY = {"confirmation": "BUYER_CONFIRMATION", "independentVerification": "NOT_PERFORMED", "originalResult": "NOT_INCLUDED",
                    "companyAuthority": "NOT_INDEPENDENTLY_VERIFIED", "externalSignature": "NOT_CHECKED", "payment": "NOT_CHECKED"}


def _subject_extensions(value, handlers):
    if isinstance(value, dict):
        if "extensions" in value or "critical" in value:
            check_extensions(value, handlers)
        for key, child in value.items():
            if key not in ("extensions", "critical"):
                _subject_extensions(child, handlers)
    elif isinstance(value, list):
        for child in value:
            _subject_extensions(child, handlers)


def verify_summary(summary, trust, handlers):
    origin = issuer_origin_of_did(summary.get("issuer"))
    check_schema(summary, SCHEMAS[SUMMARY])
    status_id = summary["credentialStatus"].get("id") if isinstance(summary.get("credentialStatus"), dict) else None
    demand(summary["schema"] == SUMMARY and same(summary["@context"], SUMMARY_CONTEXTS) and same(summary["type"], ["VerifiableCredential", "ConformitySummary"])
           and summary["credentialStatus"].get("type") == "ConformityStatus" and isinstance(status_id, str) and status_id.startswith("https://"), "SUMMARY_SHAPE_INVALID")
    subject = summary["credentialSubject"]
    demand(subject.get("id") and subject.get("title") and isinstance(subject.get("criteria"), list) and subject.get("introductionBasis") == "PARTY_DESCRIPTION"
           and subject.get("coverage") == "PUBLIC_SELECTED_RESULTS_NOT_COMPLETE_HISTORY" and same(subject.get("verification"), SUMMARY_BOUNDARY), "SUMMARY_BOUNDARY_INVALID")
    demand(_URI.match(subject["id"]) is not None, "INVALID_SUBJECT_ID")
    require_time(summary["validFrom"])
    _subject_extensions(subject, handlers)
    proof = summary["proof"]
    demand(proof.get("created") == summary["validFrom"], "SUMMARY_TIME_MISMATCH")
    demand(isinstance(proof, dict) and set(proof) == {"@context", "type", "cryptosuite", "created", "verificationMethod", "proofPurpose", "proofValue"}
           and proof["type"] == "DataIntegrityProof" and proof["cryptosuite"] == "eddsa-jcs-2022" and proof["proofPurpose"] == "assertionMethod"
           and same(proof["@context"], summary["@context"]) and isinstance(proof["proofValue"], str) and proof["proofValue"].startswith("z"), "INVALID_PROOF")
    did = issuer_did(origin)
    demand(isinstance(proof["verificationMethod"], str) and proof["verificationMethod"].startswith(did + "#"), "ISSUER_IDENTIFIER_MISMATCH")
    signature = base58_decode(proof["proofValue"][1:])
    demand(len(signature) == 64, "INVALID_SIGNATURE")
    options = {k: v for k, v in proof.items() if k != "proofValue"}
    document = {k: v for k, v in summary.items() if k != "proof"}
    public_key = KeyPolicy(trust).key(origin, proof["verificationMethod"][len(did) + 1:], proof["created"])
    signed = hashlib.sha256(canonical_bytes(options)).digest() + hashlib.sha256(canonical_bytes(document)).digest()
    demand(_ed25519.verify(public_key, signed, signature), "INVALID_SIGNATURE")
    return {"schema": REPORT_10, "issuer": origin, "status": "VERIFIED_WITH_LIMITATIONS", "closure": "NOT_ESTABLISHED",
            "disclosures": {"disclosed": 0, "total": 0}, "reasons": ["ACTOR_ATTRIBUTION_RECORDER_ASSERTION", "PUBLIC_SUMMARY_NOT_FULL_RECORD"],
            "currentStatus": "NOT_CHECKED"}


# ---------- entry point ----------
def _unique(items):
    out = []
    for item in items:
        if item not in out:
            out.append(item)
    return out


def invalid_report(code):
    return {"schema": REPORT_10, "status": "INVALID", "closure": "NOT_ESTABLISHED", "disclosures": {"disclosed": 0, "total": 0},
            "reasons": [code if code in REASONS else "INVALID_CONFORMITY_INPUT"]}


def verify_artifact(artifact, trust, checked_at=None, expected_status=None, handlers=None):
    """Verify a Conformity artifact offline and return the verification report (a dict).

    `artifact`: bytes as received (a Package, Status or Summary JSON document, or a compact SD-JWT presentation),
    or an already-parsed JSON value or SD-JWT string. `trust`: the relying party's issuer keys,
    `{"issuers": {"https://issuer.example": [{"id", "publicKeyPem", "status", "validFrom"?, "validUntil"?}]}}`.
    `checked_at` and `expected_status` (`issuer`, `resultId`, `headDigest`) are required for a Status.
    `handlers` names the critical extensions the caller supports (none by default).
    Raises UnsupportedEvidence for a 1.1 Package with anchoring evidence; every other problem is an INVALID report.
    """
    handlers = handlers or {}
    try:
        if isinstance(artifact, (bytes, bytearray)):
            text = decode_utf8(bytes(artifact))
            artifact = parse_text(text, 17 * 1024 * 1024) if text.lstrip().startswith("{") else text.strip()
        elif isinstance(artifact, str) and artifact.lstrip().startswith("{"):
            artifact = parse_text(artifact, 17 * 1024 * 1024)
        if isinstance(artifact, str):
            return verify_presentation(artifact.strip(), trust, handlers)
        if not isinstance(artifact, dict):
            raise Fail("UNSUPPORTED_CONFORMITY_ARTIFACT")
        schema = artifact.get("schema")
        if schema == PACKAGE:
            return verify_package(artifact, trust, handlers)
        if schema == SUMMARY:
            return verify_summary(artifact, trust, handlers)
        if schema == STATUS:
            demand(isinstance(expected_status, dict) and checked_at is not None, "STATUS_BINDING_AND_CLOCK_REQUIRED")
            return verify_status(artifact, trust, expected_status, checked_at, handlers)
        if "presentation" in artifact or "sdJwt" in artifact:
            # A presentation is only the compact SD-JWT; an object carrying it is not a format of its own.
            demand(not (_leaks(artifact) or any(k in artifact for k in ("tsto", "jepEvents", "files"))), "PARTIAL_PRESENTATION_LEAKS_COMMITTED_CONTENT")
            raise Fail("INVALID_PARTIAL_PRESENTATION")
        raise Fail("UNSUPPORTED_CONFORMITY_ARTIFACT")
    except UnsupportedEvidence:
        raise
    except (Fail, InputError) as error:
        return invalid_report(error.code)
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        # A member the checks above needed was missing or of the wrong type after the schema step.
        return invalid_report("INVALID_CONFORMITY_INPUT")


verify_record = verify_artifact
