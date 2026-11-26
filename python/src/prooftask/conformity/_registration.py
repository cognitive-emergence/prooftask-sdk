"""Offline verification of optional public registration in a ProofTask result file."""
import base64
import hashlib
import re
import subprocess

from . import _ed25519
from ._anchor_policy import DEFAULT_TRUST
from ._json import is_integer, parse_bytes
from ._timestamp import timestamp
from .verifier import Fail, KeyPolicy, b64url_decode, canonical_time

PROOF = "prooftask.registration-proof/v1"
HEAD = "prooftask.registration-tree-head/v1"
COMMITMENT = b"prooftask.log-commitment/v1"
HEX = re.compile(r"[a-f0-9]{64}")


def require(condition, reason="REGISTRATION_PROOF_INVALID"):
    if not condition:
        raise ValueError(reason)


def hex_digest(value):
    require(isinstance(value, str) and HEX.fullmatch(value))
    return bytes.fromhex(value)


def signed_head(token, keys, issuer):
    invalid = "REGISTRATION_TREE_HEAD_INVALID"
    require(isinstance(token, str) and len(token) <= 4096, invalid)
    require(re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token), invalid)
    header, payload, sig = token.split(".")
    try:
        meta, head = (parse_bytes(b64url_decode(part), 4096) for part in (header, payload))
        signature = b64url_decode(sig)
    except (ValueError, Fail) as error:
        raise ValueError(invalid) from error
    require(isinstance(meta, dict) and set(meta) == {"alg","kid","typ"} and meta["alg"] == "EdDSA"
            and meta["typ"] == HEAD and isinstance(meta["kid"], str) and meta["kid"] and len(signature) == 64, invalid)
    require(isinstance(head, dict) and set(head) == {"schema","log","treeSize","rootHash","timestamp"}
            and head["schema"] == HEAD and is_integer(head["treeSize"], 0)
            and canonical_time(head["timestamp"]) and isinstance(head["rootHash"], str) and HEX.fullmatch(head["rootHash"])
            and isinstance(head["log"], str) and re.fullmatch(r"https://[^/?#\s]+", head["log"]), invalid)
    try:
        public_key = keys.key(issuer, meta["kid"], head["timestamp"])
    except Fail as error:
        raise ValueError("REGISTRATION_TREE_HEAD_KEY_UNTRUSTED") from error
    require(_ed25519.verify(public_key, (header + "." + payload).encode("ascii"), signature),
            "REGISTRATION_TREE_HEAD_SIGNATURE_INVALID")
    return head, meta["kid"]


def inclusion_root(leaf, index, size, path):
    """RFC 9162 inclusion path, including nodes promoted on a non-power-of-two right edge."""
    value = hashlib.sha256(b"\x00" + leaf).digest()
    last = size - 1
    for encoded in path:
        sibling = hex_digest(encoded)
        require(last > 0, "REGISTRATION_INCLUSION_INVALID")
        if index % 2 or index == last:
            pair = sibling + value
            while index and not index % 2:
                index //= 2
                last //= 2
        else:
            pair = value + sibling
        value = hashlib.sha256(b"\x01" + pair).digest()
        index //= 2
        last //= 2
    require(last == 0, "REGISTRATION_INCLUSION_INVALID")
    return value.hex()


def tree_time(token, signed, trust):
    try:
        roots = (DEFAULT_TRUST if trust is None else trust)["timeStampRoots"]
        require(isinstance(roots, list) and all(isinstance(root, dict) and isinstance(root.get("pem"), str) for root in roots))
        stamped = timestamp(base64.b64decode(token, validate=True), hashlib.sha256(signed.encode("ascii")).hexdigest(), roots)
        return {k: stamped[k] for k in ("status", "genTime", "tsa")}
    except (ValueError, TypeError, KeyError, IndexError, OverflowError, OSError, subprocess.SubprocessError):
        return {"status": "FAILED"}


def verify_entries(proof, identity, root):
    size = int(proof["treeSize"])
    issuance_index = None
    latest = {"code": "BUYER_CONFIRMED", "sequence": 0}
    entries = proof["entries"]
    require(isinstance(entries, list) and 1 <= len(entries) <= 64)
    digest = hex_digest(proof["recordDigest"])
    for entry in entries:
        fields = {"type", "salt", "leafIndex", "auditPath"}
        require(isinstance(entry, dict) and fields <= set(entry))
        index, path = entry["leafIndex"], entry["auditPath"]
        require(is_integer(index, 0, size - 1) and isinstance(path, list) and len(path) <= 64)
        issuance = entry["type"] == "ISSUANCE"
        if issuance:
            require(set(entry) == fields)
            result_id = identity["resultId"].encode("utf-8")
            require(1 <= len(result_id) <= 1024)
            kind, payload = b"\x01", len(result_id).to_bytes(2, "big") + result_id
            if issuance_index is None:
                issuance_index = int(index)
        else:
            require(entry["type"] == "STATUS" and set(entry) == fields | {"statusCode", "statusSequence"})
            code, seq = entry["statusCode"], entry["statusSequence"]
            require(isinstance(code, str) and re.fullmatch(r"[A-Z][A-Z_]{0,63}", code) and is_integer(seq, 1, 0xffffffff))
            payload = int(seq).to_bytes(4, "big") + bytes([len(code)]) + code.encode("ascii")
            kind = b"\x02"
            if seq > latest["sequence"]:
                latest = {"code": code, "sequence": int(seq)}
        leaf = hashlib.sha256(COMMITMENT + kind + digest + payload + hex_digest(entry["salt"])).digest()
        require(inclusion_root(leaf, int(index), size, path) == root,
                "REGISTRATION_RECORD_MISMATCH" if issuance else "REGISTRATION_INCLUSION_INVALID")
    require(issuance_index is not None, "REGISTRATION_ISSUANCE_NOT_INCLUDED")
    return issuance_index, latest


def registration_report(record, presentation, evidence, present, trust, anchor_trust):
    # record and presentation are authenticated by verify_package before this function is called.
    agreement = record["specification"]["extensions"]["com.prooftask.agreement"]
    agreed = (agreement.get("trustPolicy") or {}).get("registration") == {"requirement": "REQUIRED"}
    if not present:
        return {"agreed": True, "status": "NOT_PRESENT"} if agreed else None
    report = {"agreed": agreed}
    try:
        basic = {"schema", "pending", "recordDigest"}
        require(isinstance(evidence, dict) and basic <= set(evidence) and evidence["schema"] == PROOF)
        hex_digest(evidence["recordDigest"])
        pending = evidence["pending"]
        require(is_integer(pending, 0))
        digest = hashlib.sha256(presentation.split("~", 1)[0].encode("ascii")).hexdigest()
        if set(evidence) == basic:
            require(pending > 0)
            return dict(report, status="PENDING", pending=int(pending))
        fields = basic | {"treeSize", "signedTreeHead", "entries"}
        require(fields <= set(evidence) <= (fields | {"treeHeadAnchors"}) and is_integer(evidence["treeSize"], 1))
        anchors = evidence.get("treeHeadAnchors", {})
        require(isinstance(anchors, dict) and set(anchors) <= {"timeStamp"})
        if "timeStamp" in anchors:
            token = anchors["timeStamp"]
            require(isinstance(token, str) and len(token) <= 90000 and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", token))
        head, kid = signed_head(evidence["signedTreeHead"], KeyPolicy(trust), record["identity"]["issuer"])
        require(head["treeSize"] == evidence["treeSize"])
        index, latest = verify_entries(evidence, record["identity"], head["rootHash"])
        report.update(status="VERIFIED", log=head["log"], treeSize=int(head["treeSize"]), rootHash=head["rootHash"],
                      treeHeadAt=head["timestamp"], keyId=kid, issuanceLeafIndex=index, latestStatus=latest,
                      binding="ISSUED_RECORD" if evidence["recordDigest"] == digest else "SAME_RESULT")
        snapshot = record["extensions"].get("com.prooftask.snapshot", {})
        conclusion = snapshot.get("conclusion") if isinstance(snapshot, dict) else None
        state = conclusion.get("state") if isinstance(conclusion, dict) else None
        if isinstance(state, str):
            report["statusMatchesRecord"] = state == latest["code"]
        if pending:
            report["pending"] = int(pending)
        if "timeStamp" in anchors:
            report["treeHeadTime"] = tree_time(anchors["timeStamp"], evidence["signedTreeHead"], anchor_trust)
        return report
    except (ValueError, Fail) as error:
        return {"agreed": agreed, "status": "FAILED", "reason": str(error)}
