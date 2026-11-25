"""Verify optional Conformity Package evidence, independently from the signed Record and JEP checks."""
import base64
import hashlib
import re
import subprocess

from ._anchor_policy import DEFAULT_TRUST
from ._bitcoin import verify_bitcoin
from ._json import canonical_bytes, is_integer, parse_bytes
from ._timestamp import prepare_validation, pem_blocks, timestamp


INDEX = "evidence/anchors.json"
TYPED = "https://humanjudgment.org/ns/conformity-anchors/1.3"
LEGACY = "https://humanjudgment.org/ns/conformity-anchors/1.0"
UUID = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z")
HEX = re.compile(r"[a-f0-9]{64}\Z")
PROOF_ERRORS = (KeyError, TypeError, ValueError, IndexError, OverflowError, OSError, subprocess.SubprocessError)


def need(ok):
    if not ok:
        raise ValueError("invalid anchor evidence")


def exact(value, required, optional=()):
    need(isinstance(value, dict) and set(required) <= value.keys() <= set(required) | set(optional))


def path(value, directory):
    need(isinstance(value, str) and value.startswith("evidence/" + directory + "/") and len(value) < 200
         and not any(p in ("", ".", "..") for p in value.split("/")) and ".." not in value
         and re.fullmatch(r"[a-z0-9/._-]+", value))


def validate_index(raw):
    index = parse_bytes(raw, 1024 * 1024)
    typed = index["schema"] == TYPED
    need(typed or (index["schema"] == LEGACY and len(raw) <= 65536))
    exact(index, ("schema", "subject", "items"), () if typed else ("omitted",))
    exact(index["subject"], ("alg", "digest"))
    need(index["subject"]["alg"] == "sha-256" and HEX.fullmatch(index["subject"]["digest"]))
    need(isinstance(index["items"], list) and len(index["items"]) <= (1024 if typed else 32))
    if "omitted" in index:
        need(is_integer(index["omitted"], 1, 10000))
    referenced = {INDEX}
    used_tokens = set()
    for item in index["items"]:
        time = item["type"] == "rfc3161"
        need(time or item["type"] == "opentimestamps")
        if typed:
            sub = item["subject"]
            if sub["kind"] == "EVENT_HEAD":
                exact(sub, ("kind", "eventId", "eventHash"))
                need(time and UUID.fullmatch(sub["eventId"]) and re.fullmatch(r"sha256:[a-f0-9]{64}", sub["eventHash"]))
            else:
                exact(sub, ("kind", "digest"))
                need(sub["kind"] in ("RECORD", "PARTY_SIGNATURE") and HEX.fullmatch(sub["digest"]))
                if sub["kind"] == "RECORD":
                    need(sub["digest"] == index["subject"]["digest"])
                else:
                    need(time)
        if time:
            exact(item, ("type", "token", "subject", "assurance") if typed else ("type", "token"),
                  ("renewals", "validation") if typed else ("renewals", "validation", "target"))
            if typed:
                need(item["assurance"] in ("BEST_EFFORT", "CONTRACTED"))
            if "target" in item:
                target = item["target"]
                exact(target, ("alg", "digest", "kind"))
                need(target["kind"] == "party-signature" and target["alg"] == "sha-256" and HEX.fullmatch(target["digest"]))
            if "renewals" in item:
                need(isinstance(item["renewals"], list) and 1 <= len(item["renewals"]) <= 32)
                for renewal in item["renewals"]:
                    exact(renewal, ("token",), ("validation",))
            for ref in [item] + item.get("renewals", []):
                path(ref["token"], "rfc3161")
                if typed:
                    need(ref["token"] not in used_tokens)
                    used_tokens.add(ref["token"])
                referenced.add(ref["token"])
                if "validation" in ref:
                    path(ref["validation"], "ltv")
                    referenced.add(ref["validation"])
        else:
            exact(item, ("type", "subject", "proof") if typed else ("type", "proof"), ("headers",))
            path(item["proof"], "ots")
            referenced.add(item["proof"])
            if "headers" in item:
                headers = item["headers"]
                exact(headers, ("path", "fromHeight"))
                need(is_integer(headers["fromHeight"], 0))
                path(headers["path"], "bitcoin")
                referenced.add(headers["path"])
    return index, referenced


def obj(value):
    return value if isinstance(value, dict) else {}


def event_heads(events):
    previous = None
    valid = True
    seen = set()
    result = []
    for event in events:
        workflow = obj(obj(event.get("ext")).get("com.prooftask.workflow"))
        event_id = workflow.get("workflow_event_id")
        kind, time = workflow.get("workflow_kind"), workflow.get("recorded_at")
        digest = "sha256:" + hashlib.sha256(canonical_bytes(event)).hexdigest()
        if previous is None:
            task, agreement = workflow.get("task_id"), workflow.get("agreement_digest")
        valid = bool(valid and isinstance(event_id, str) and UUID.fullmatch(event_id) and event_id not in seen
                     and event.get("id") == "urn:uuid:" + event_id and workflow.get("previous_event_hash", False) == previous
                     and workflow.get("judgment_scope") == "buyer_confirmed_delivery"
                     and isinstance(task, str) and task == workflow.get("task_id") and isinstance(agreement, str)
                     and agreement == workflow.get("agreement_digest") and isinstance(time, str))
        if isinstance(event_id, str):
            seen.add(event_id)
            if isinstance(time, str) and (kind in ("SUBMIT", "REVIEW") or
                                         (kind == "SUPPLIER_RESPONSE" and obj(workflow.get("payload")).get("action") == "ACCEPT")):
                result.append({"eventId": event_id, "eventHash": digest, "eventKind": kind, "recorderTime": time, "hashMatches": valid})
        previous = digest
    return result


def native_agreement(record):
    return obj(record["specification"].get("extensions")).get("com.prooftask.agreement")


def selected_time(record):
    policy = obj(obj(native_agreement(record)).get("trustPolicy"))
    return obj(policy.get("time")).get("requirement") in ("REQUIRED", "OPTIONAL")


def restricted_tsa(trust, record):
    roots, oids = trust["timeStampRoots"], trust.get("timeStampPolicyOids")
    if selected_time(record):
        frozen = record["specification"]["extensions"]["com.prooftask.agreement"]["trustPolicy"]["time"]
        pins = frozen.get("rootSha256")
        if pins:
            selected = []
            for root in roots:
                for der in pem_blocks(root["pem"].encode("ascii"), b"CERTIFICATE"):
                    fingerprint = hashlib.sha256(der).hexdigest()
                    if fingerprint in pins:
                        pem = "-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(der).decode("ascii") + "-----END CERTIFICATE-----\n"
                        selected.append(dict(root, pem=pem, sha256=fingerprint))
            roots = selected
        if frozen.get("policyOids"):
            oids = [o for o in frozen["policyOids"] if not oids or o in oids] or ["0"]
    return roots, oids


def select_time(entries):
    return min(entries, key=lambda t: (t["revocation"] != "CHECKED", t["latestTime"]))


def verify_anchors(presentation, record, events, read, trust=None):
    digest = hashlib.sha256(presentation.split("~", 1)[0].encode("ascii")).hexdigest()
    absent = {"status": "NOT_PRESENT"}
    failed = {"status": "FAILED"}
    report = {"subject": {"alg": "sha-256", "digest": digest}, "time": absent, "bitcoin": absent, "earliestIndependentTime": None}
    try:
        raw = read(INDEX, 1024 * 1024)
    except FileNotFoundError:
        raw = None
    except ValueError:
        return dict(report, time=failed, bitcoin=failed), ["ANCHOR_EVIDENCE_INVALID"], {INDEX}, False
    required = selected_time(record)
    if raw is None:
        reasons = ["ANCHOR_EVIDENCE_NOT_PRESENT"]
        heads = event_heads(events) if required else []
        if heads:
            report["eventHeads"] = [dict(h, time=absent) for h in heads]
            reasons.append("EVENT_HEAD_TIME_ANCHOR_NOT_PRESENT")
        return report, reasons, set(), required
    try:
        index, paths = validate_index(raw)
    except PROOF_ERRORS:
        return dict(report, time=failed, bitcoin=failed), ["ANCHOR_EVIDENCE_INVALID"], {INDEX}, False
    typed = index["schema"] == TYPED
    items = index["items"]
    if index["subject"]["digest"] != digest:
        if any(i["type"] == "rfc3161" for i in items):
            report["time"] = failed
        if any(i["type"] == "opentimestamps" for i in items):
            report["bitcoin"] = failed
        return report, ["ANCHOR_SUBJECT_MISMATCH"], paths, typed
    trust = DEFAULT_TRUST if trust is None else trust
    roots, oids = restricted_tsa(trust, record)
    times, blocks, unbound, independent = [], [], [], []
    signatures, matches = {}, {}
    heads = event_heads(events) if typed or required else []
    by_id = {h["eventId"]: h for h in heads}
    reasons = ["ANCHOR_EVIDENCE_OMITTED"] if "omitted" in index else []
    failures = set()
    # Most entries refer to the same LTV snapshot. Reuse its parsed certificates and CRLs within this call.
    # Keep only the most recent snapshot, independently of the number of index entries.
    material_path, material = object(), None

    def token(entry, imprint):
        data = read(entry["token"], 65536)
        nonlocal material_path, material
        path = entry.get("validation")
        if path != material_path:
            pem = read(path, 1024 * 1024) if path else b""
            material = prepare_validation(roots, pem)
            material_path = path
        try:
            return data, timestamp(data, imprint, roots, policies=oids, material=material)
        except ValueError as error:
            if str(error) == "TRUST_TIME_POLICY_MISMATCH":
                failures.add(str(error))
            raise

    def check_time(item, imprint):
        previous, result = token(item, imprint)
        if "renewals" in item:
            latest = result["genTime"]
            renewal = {"status": "VERIFIED", "count": len(item["renewals"])}
            try:
                for ref in item["renewals"]:
                    previous, nxt = token(ref, hashlib.sha256(previous).hexdigest())
                    need(nxt["genTime"] >= latest)
                    latest = nxt["genTime"]
                renewal["latestGenTime"] = latest
            except PROOF_ERRORS:
                renewal["status"] = "FAILED"
                failures.add("TIME_ANCHOR_RENEWAL_NOT_VERIFIED")
            result["renewals"] = renewal
        return result

    for item in items:
        sub = item.get("subject", {})
        if sub.get("kind") == "EVENT_HEAD":
            event_id, event_hash = sub["eventId"], sub["eventHash"]
            head = by_id.get(event_id)
            same = bool(head and head["eventHash"] == event_hash)
            bound = bool(same and head["hashMatches"])
            entry = {"eventId": event_id, "eventHash": event_hash, "hashMatches": bound, "assurance": item["assurance"], "time": failed}
            if head:
                entry.update(eventKind=head["eventKind"], recorderTime=head["recorderTime"])
            if bound:
                try:
                    entry["time"] = check_time(item, event_hash[7:])
                except PROOF_ERRORS:
                    pass
            if entry["time"]["status"] == "FAILED":
                reasons.append("EVENT_HEAD_TIME_ANCHOR_NOT_VERIFIED")
            elif entry["time"]["revocation"] == "CHECKED":
                entry["existedNoLaterThan"] = entry["time"]["latestTime"]
            else:
                reasons.append("TIME_ANCHOR_REVOCATION_NOT_CHECKED")
            (matches.setdefault(event_id, []) if same else unbound).append(entry)
        elif item["type"] == "rfc3161":
            party = sub.get("digest") if sub.get("kind") == "PARTY_SIGNATURE" else item.get("target", {}).get("digest")
            entries = signatures.setdefault(party, []) if party else times
            try:
                result = check_time(item, party or digest)
                if typed:
                    result["assurance"] = item["assurance"]
                entries.append(result)
            except PROOF_ERRORS:
                failures.add("SIGNATURE_TIME_ANCHOR_NOT_VERIFIED" if party else "TIME_ANCHOR_NOT_VERIFIED")
        else:
            try:
                agreement = native_agreement(record)
                chain = obj(obj(obj(agreement).get("trustPolicy")).get("publicChain"))
                need("com.prooftask.agreement" not in obj(record["specification"].get("extensions")) or (chain.get("creatorOptIn") is True and chain.get("requirement") in ("OPTIONAL", "REQUIRED")))
                proof = read(item["proof"], 1024 * 1024)
                headers = item.get("headers")
                header_bytes = read(headers["path"], 60000 * 80) if headers else None
                blocks.append(verify_bitcoin(proof, digest, trust["bitcoin"], header_bytes, int(headers["fromHeight"]) if headers else 0))
            except PROOF_ERRORS:
                failures.add("BITCOIN_ANCHOR_NOT_VERIFIED")
    if heads or unbound:
        entries = []
        for head in heads:
            if head["eventId"] in matches:
                entries.extend(matches[head["eventId"]])
            else:
                entries.append(dict(head, time=absent))
                reasons.append("EVENT_HEAD_TIME_ANCHOR_NOT_PRESENT")
        report["eventHeads"] = entries + unbound
    if times:
        chosen = select_time(times).copy()
        if not typed:
            chosen.pop("latestTime")
        report["time"] = chosen
        if chosen["revocation"] != "CHECKED":
            reasons.append("TIME_ANCHOR_REVOCATION_NOT_CHECKED")
        independent.extend(t["latestTime"] for t in times if t["revocation"] == "CHECKED")
    elif "TIME_ANCHOR_NOT_VERIFIED" in failures:
        report["time"] = failed
    for reason in ("TIME_ANCHOR_NOT_VERIFIED", "TIME_ANCHOR_RENEWAL_NOT_VERIFIED", "SIGNATURE_TIME_ANCHOR_NOT_VERIFIED", "TRUST_TIME_POLICY_MISMATCH"):
        if reason in failures:
            reasons.append(reason)
    if signatures:
        report["signatures"] = []
        for digest, values in signatures.items():
            best = select_time(values).copy() if values else failed.copy()
            best.pop("policy", None)
            report["signatures"].append({"digest": digest, "time": best})
    verified = [b for b in blocks if b[0]["status"] == "VERIFIED"]
    if verified:
        report["bitcoin"] = min(verified, key=lambda b: b[0]["height"])[0]
        reasons.append("BITCOIN_POW_LINKED_NOT_FULL_NODE")
        independent.extend(b[2] for b in verified)
    elif blocks:
        report["bitcoin"] = next((b[0] for b in blocks if "height" in b[0]), blocks[0][0])
        reasons.append("BITCOIN_CHECKPOINT_NOT_HELD" if any(b[1] == "BITCOIN_CHECKPOINT_NOT_HELD" for b in blocks) else "BITCOIN_ANCHOR_PENDING")
    if "BITCOIN_ANCHOR_NOT_VERIFIED" in failures:
        if not blocks:
            report["bitcoin"] = failed
        reasons.append("BITCOIN_ANCHOR_NOT_VERIFIED")
    if report["time"] == absent and report["bitcoin"] == absent:
        reasons.append("ANCHOR_EVIDENCE_NOT_PRESENT")
    report["earliestIndependentTime"] = min(independent, default=None)
    return report, list(dict.fromkeys(reasons)), paths, typed or required
