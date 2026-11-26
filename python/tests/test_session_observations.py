"""Session evidence boundaries for the native Package reader."""
from copy import deepcopy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from prooftask.conformity._sessions import _request_digest, _supplier_authorized_at, session_observations
from prooftask.conformity.verifier import epoch_ms, json_digest


class SessionObservationTest(unittest.TestCase):
    def inspect(self, observation, actor_changes=None, event_changes=None):
        at = "2026-11-21T10:02:00.000Z"
        actor = {"id": "fixture@example.test", "organizationId": "fixture-party",
                 "bindingMethod": "verified_supplier_account", **(actor_changes or {})}
        if observation is not None:
            actor["sessionAuthentication"] = observation
        result, salt = "urn:result:fixture", "fixture"
        who = "urn:conformity:actor:" + json_digest({"resultId": result, "partyId": actor["organizationId"],
                                                     "principal": actor["id"], "salt": salt})[7:]
        event_id = "2d28895a-fa9b-42f6-a659-3b76118485df"
        workflow = {"task_id": "task", "agreement_digest": "agreement", "workflow_event_id": event_id,
                    "workflow_kind": "REVIEW", "actor": actor, "payload": {"action": "ACCEPT"},
                    "previous_event_hash": None, "recorded_at": at, "judgment_scope": "buyer_confirmed_delivery"}
        event = {"verb": "J", "who": who, "id": "urn:uuid:" + event_id, "when": epoch_ms(at) // 1000,
                 "ext": {"com.prooftask.workflow": workflow}, **(event_changes or {})}
        digest = json_digest(event)
        record = {"identity": {"resultId": result}, "issuance": {"issuedAt": at},
                  "extensions": {"com.prooftask.source": {"agreementDigest": "agreement", "eventDigests": [digest]}},
                  "specification": {"extensions": {"com.prooftask.actor-salt": salt, "com.prooftask.agreement": {"taskId": "task"}}},
                  "agreements": [], "deliveries": [], "decisions": [
                      {"eventDigest": digest, "action": "ACCEPT", "recordedAt": at, "actor": {"id": who, "extensions": {"com.prooftask.actor": actor}}}]}
        return session_observations(record, [event])

    def test_distinct_method_and_times(self):
        for method in ("EMAIL_CODE", "APPLE", "GOOGLE", "GITHUB", "WORKSPACE_SSO"):
            observation = {"method": method, "authenticatedAt": "2026-11-21T10:00:00.000Z",
                           "passkeyVerifiedAt": "2026-11-21T10:01:00.000Z"}
            row, = self.inspect(observation)
            self.assertEqual({key: row[key] for key in observation}, observation)
            self.assertEqual(row["action"], "ACCEPT")
            self.assertNotEqual(row["recordedAt"], row["passkeyVerifiedAt"])
        self.assertEqual(self.inspect(None), [])

    def test_refuses_inconsistent_times_fields_and_actors(self):
        signed_in = {"method": "EMAIL_CODE", "authenticatedAt": "2026-11-21T10:00:00.000Z"}
        for change in ({"method": "UNVERIFIED"}, {"authenticatedAt": "2026-11-21T10:02:00.001Z"},
                       {"passkeyVerifiedAt": "2026-11-21T09:59:59.999Z"}, {"passkeyVerifiedAt": "2026-11-21T10:03:00.000Z"},
                       {"authenticatedAt": "invalid"}, {"device": "unexpected"}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "INVALID_SESSION_AUTHENTICATION"):
                self.inspect(dict(signed_in, **change))
        for change in ({"execution": {"grantId": "fixture"}}, {"attribution": {"basis": "REPORTER_ASSERTION"}},
                       {"bindingMethod": "platform_reporter_assertion"}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "INVALID_SESSION_AUTHENTICATION"):
                self.inspect(signed_in, actor_changes=change)
        for change in ({"who": "another actor"}, {"when": 1}, {"id": "urn:uuid:other"}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "SESSION_SOURCE_BINDING_INVALID"):
                self.inspect(signed_in, event_changes=change)


    def test_prepared_materials_must_match_the_authorized_proposal(self):
        published, submitted = "2026-11-21T10:00:00.000Z", "2026-11-21T10:02:00.000Z"
        materials = {"summary": "Fixture report", "items": [{"criterionId": "check"}]}
        actor = {"id": "supplier", "role": "provider", "organizationId": "firm", "tenantId": "tenant"}
        pre = {"statement": "ACCEPT_IF_UNCHANGED", "verifiedAt": published, "reason": "Approved as published",
               "preparedDeliveryDigest": _request_digest({"purpose": "prepared-delivery-materials/v1", "proposalId": "p",
                                                          "version": 2, "nonce": "salt", "materials": materials})}
        origin = {"schema": "prooftask.supplier-proposal/v1", "proposalId": "p", "version": 2,
                  "publishedAt": published, "publishedBy": actor, "preAcceptance": pre}
        origin["digest"] = _request_digest(origin)
        ref = {"proposalId": "p", "version": 2, "proposalDigest": origin["digest"]}
        responder = dict(actor, scope="RESULT_AGREEMENT_ACCEPT", accountBinding={"verifiedAt": published},
                         bindingMethod="verified_supplier_account", bindingReference="urn:prooftask:proposal-pre-acceptance:p:2")
        steps = [
            {"workflow_kind": "BUYER_COMMIT", "recorded_at": submitted, "payload": {"supplierProposal": origin}},
            {"workflow_kind": "SUPPLIER_REPRESENTATIVE", "recorded_at": submitted},
            {"workflow_kind": "SUPPLIER_RESPONSE", "recorded_at": submitted, "actor": responder,
             "payload": {"action": "ACCEPT", "preAcceptance": ref, "reason": pre["reason"]}},
            {"workflow_kind": "SUBMIT", "recorded_at": submitted, "actor": dict(responder, scope="DELIVERY_SUBMIT"),
             "payload": dict(materials, preparedFrom={"proposalDigest": origin["digest"], "nonce": "salt"})},
        ]
        self.assertEqual(_supplier_authorized_at(steps, 2), published)
        self.assertEqual(_supplier_authorized_at(steps, 3), published)
        for path in (("summary",), ("preparedFrom", "nonce"), ("preparedFrom", "proposalDigest")):
            changed = deepcopy(steps)
            target = changed[3]["payload"]
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = "different"
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "ADVANCE_AUTHORIZATION_BINDING_INVALID"):
                _supplier_authorized_at(changed, 3)
        steps[2]["payload"]["preAcceptance"]["version"] = 3
        for index in (2, 3):
            with self.assertRaisesRegex(ValueError, "ADVANCE_AUTHORIZATION_BINDING_INVALID"):
                _supplier_authorized_at(steps, index)


if __name__ == "__main__":
    unittest.main()
