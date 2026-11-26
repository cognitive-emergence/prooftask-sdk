"""ProofTask session observations from an authenticated native package."""

import re

from ._json import same
from .verifier import canonical_time, critical_manifest, epoch_ms, json_digest

PRIVATE_CONTENT = "com.prooftask.private-content"
_PRIVATE_FIELDS = {"schema": "prooftask.private-content/v1", "commitment": "sd-jwt-disclosure-sha256", "titles": "CLEAR"}
_METHODS = {"EMAIL_CODE", "GOOGLE", "APPLE", "GITHUB", "WORKSPACE_SSO"}


def check_concern_history(entry, event, record):
    """Bind a product-specific concern in signed history before the common JEP signature check."""
    workflow = event["ext"].get("com.prooftask.workflow")
    if (not isinstance(record["extensions"].get("com.prooftask.snapshot"), dict)
            or "org.humanjudgment.record-binding" in event["ext"] or not isinstance(workflow, dict)
            or workflow.get("workflow_kind") != "WORKFLOW_CONTROL" or not isinstance(workflow.get("payload"), dict)
            or workflow["payload"].get("action") not in {"REPORT_CONCERN", "RESPOND_CONCERN", "CLOSE_CONCERN"}
            or entry["objectId"] != entry["id"] or event["id"] != entry["id"]
            or entry["recordedAt"] != workflow.get("recorded_at")):
        raise ValueError("SESSION_SOURCE_BINDING_INVALID")


def session_observations(record, events):
    """Called only after full package verification; returns no partial list on a failed binding."""
    source = record["extensions"].get("com.prooftask.source")
    spec = record["specification"]["extensions"]
    salt = spec.get("com.prooftask.actor-salt")
    agreement = spec.get("com.prooftask.agreement")
    if not isinstance(source, dict) or not isinstance(agreement, dict) or not isinstance(salt, str):
        raise ValueError("NATIVE_SOURCE_REQUIRED")
    sealed = "privateContent" in (agreement.get("trustPolicy") or {})
    if sealed:
        if (agreement["trustPolicy"]["privateContent"] != {"mode": "SEALED", "titles": "CLEAR"}
                or record["extensions"].get(PRIVATE_CONTENT) != _PRIVATE_FIELDS
                or critical_manifest(record) != [{"path": "/", "keys": [PRIVATE_CONTENT]}]):
            raise ValueError("INVALID_PRIVATE_CONTENT_EXTENSION")
    elif PRIVATE_CONTENT in record["extensions"] or critical_manifest(record):
        raise ValueError("INVALID_PRIVATE_CONTENT_EXTENSION")
    digests = [json_digest(event) for event in events]
    if source.get("eventDigests") != digests:
        raise ValueError("SESSION_SOURCE_BINDING_INVALID")
    objects = {obj["eventDigest"]: (collection, obj) for collection in ("agreements", "deliveries", "decisions")
               for obj in record[collection]}
    previous = None
    previous_time = None
    observations = []
    for digest, event in zip(digests, events):
        workflow = event["ext"]["com.prooftask.workflow"]
        actor = workflow["actor"]
        at = workflow["recorded_at"]
        event_id = workflow["workflow_event_id"]
        who = "urn:conformity:actor:" + json_digest({"resultId": record["identity"]["resultId"],
            "partyId": actor["organizationId"], "principal": actor["id"], "salt": salt})[7:]
        if (not isinstance(event_id, str) or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", event_id)
                or workflow["workflow_kind"] not in {"BUYER_COMMIT", "SUPPLIER_REPRESENTATIVE", "SUPPLIER_RESPONSE",
                                                      "SUBMIT", "REVIEW", "WORKFLOW_CONTROL", "DATE_REVISION_REQUEST"}
                or workflow["judgment_scope"] != "buyer_confirmed_delivery" or event["verb"] != "J"
                or workflow["task_id"] != agreement["taskId"] or workflow["agreement_digest"] != source["agreementDigest"]
                or workflow["previous_event_hash"] != previous or event["id"] != "urn:uuid:" + event_id
                or not canonical_time(at) or at > record["issuance"]["issuedAt"] or epoch_ms(at) // 1000 != event["when"]
                or (previous_time is not None and at < previous_time) or event["who"] != who):
            raise ValueError("SESSION_SOURCE_BINDING_INVALID")
        previous, previous_time = digest, at
        kind, action = workflow["workflow_kind"], workflow["payload"].get("action")
        collection, obj = objects.get(digest, (None, None))
        expected = {"BUYER_COMMIT": "agreements", "REVIEW": "decisions", "SUBMIT": "deliveries"}.get(kind)
        if kind == "SUPPLIER_RESPONSE" and action == "ACCEPT":
            expected = "agreements"
        if collection != expected:
            raise ValueError("SESSION_SOURCE_BINDING_INVALID")
        if obj is not None:
            signed = obj["actor"]
            if (signed["id"] != who or not same(signed["extensions"].get("com.prooftask.actor"), actor)
                    or obj["recordedAt"] != at or (collection == "decisions" and obj["action"] != action)
                    or (collection == "agreements" and obj["party"] != ("SECOND_PARTY" if kind == "BUYER_COMMIT" else "FIRST_PARTY"))):
                raise ValueError("SESSION_SOURCE_BINDING_INVALID")
        if "sessionAuthentication" not in actor:
            continue
        observation = actor["sessionAuthentication"]
        if (not isinstance(observation, dict) or set(observation) - {"method", "authenticatedAt", "passkeyVerifiedAt"}
                or observation.get("method") not in _METHODS or "execution" in actor or "attribution" in actor
                or actor.get("bindingMethod") == "platform_reporter_assertion"
                or not canonical_time(observation.get("authenticatedAt")) or observation["authenticatedAt"] > at):
            raise ValueError("INVALID_SESSION_AUTHENTICATION")
        if "passkeyVerifiedAt" in observation:
            second = observation["passkeyVerifiedAt"]
            if not canonical_time(second) or not observation["authenticatedAt"] <= second <= at:
                raise ValueError("INVALID_SESSION_AUTHENTICATION")
        observations.append({"eventId": event_id, "actorId": actor["id"], "kind": workflow["workflow_kind"],
                             "recordedAt": at, **({"action": action} if isinstance(action, str) else {}), **observation})
    return observations
