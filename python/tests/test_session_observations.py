"""Session evidence boundaries for the native Package reader."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from prooftask.conformity._sessions import session_observations
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


if __name__ == "__main__":
    unittest.main()
