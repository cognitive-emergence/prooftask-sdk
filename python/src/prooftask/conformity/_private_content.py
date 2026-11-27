"""Check a holder's optional field disclosures after authenticating the signed workflow."""
import hashlib
import json
import re

from ._json import InputError, canonical_bytes
from .verifier import Fail, b64url, b64url_decode

_REFERENCE = re.compile(r"pt-sealed:1:[A-Za-z0-9_-]{43}")
_SCHEMA = "prooftask.private-content-openings/v1"


def _matches(opening, refs):
    if not isinstance(opening, dict):
        return False
    ref, path, salt, value = (opening.get(key) for key in ("ref", "path", "salt", "value"))
    if not isinstance(ref, str) or ref not in refs or not isinstance(path, str) or not path.startswith("/"):
        return False
    if len(path.encode("utf-16-le")) > 2000 or not isinstance(value, str) or not isinstance(salt, str):
        return False
    try:
        if len(b64url_decode(salt)) < 16:
            return False
        disclosure = b64url(canonical_bytes([salt, path, value]))
    except (Fail, InputError):
        return False
    return ref == "pt-sealed:1:" + b64url(hashlib.sha256(disclosure.encode("ascii")).digest())


def opening_report(record, tsto, events, wrapper):
    refs = set()
    for document in (record, tsto, *events):
        refs.update(_REFERENCE.findall(json.dumps(document, ensure_ascii=False)))
    report = {"opened": 0, "sealed": len(refs), "mismatched": 0}
    if "privateContentOpenings" not in wrapper:
        return report
    file = wrapper["privateContentOpenings"]
    if (not isinstance(file, dict) or file.get("schema") != _SCHEMA
            or not isinstance(file.get("openings"), list) or len(file["openings"]) > 4000
            or set(file) - {"schema", "resultId", "openings"}):
        return {**report, "reason": "PRIVATE_CONTENT_OPENINGS_INVALID"}
    if file.get("resultId") != record["identity"]["resultId"]:
        return {**report, "reason": "PRIVATE_CONTENT_OPENINGS_RESULT_MISMATCH"}
    opened = set()
    for opening in file["openings"]:
        if _matches(opening, refs):
            opened.add(opening["ref"])
        else:
            report["mismatched"] += 1
    report.update(opened=len(opened), sealed=len(refs) - len(opened))
    return report
