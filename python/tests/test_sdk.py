import hashlib
import hmac
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import prooftask  # noqa: E402
from prooftask import (ConflictError, ProofTaskClient, WebhookVerificationError, construct_webhook_event, paginate,  # noqa: E402
                       request_id_of, sign_webhook_payload, verify_webhook_signature, with_request_id)

SECRET = "whsec_test"
BODY = b'{"type":"agreement.confirmed","id":"evt"}'
NOW = 1795219200
TS = str(NOW)
SIGNATURE = "v1=" + hmac.new(SECRET.encode(), TS.encode() + b"." + BODY, hashlib.sha256).hexdigest()


class WebhookTests(unittest.TestCase):
    def test_signature_matches_documented_construction(self):
        self.assertEqual(sign_webhook_payload(SECRET, TS, BODY), SIGNATURE)
        self.assertEqual(sign_webhook_payload(SECRET, TS, BODY.decode()), SIGNATURE)
        verify_webhook_signature(SECRET, BODY, TS, SIGNATURE, now=NOW)
        verify_webhook_signature(SECRET, BODY, TS, SIGNATURE, now=NOW + 300)

    def test_rejections(self):
        cases = {
            "TIMESTAMP_OUT_OF_TOLERANCE": dict(now=NOW + 301),
            "SIGNATURE_MISMATCH": dict(raw_body=BODY + b" "),
            "SIGNATURE_FORMAT_INVALID": dict(signature=SIGNATURE[3:]),
            "TIMESTAMP_INVALID": dict(timestamp="2026-11-21T00:00:00Z"),
            "MISSING_HEADER": dict(signature=None),
        }
        for code, change in cases.items():
            args = dict(secret=SECRET, raw_body=BODY, timestamp=TS, signature=SIGNATURE, now=NOW)
            args.update(change)
            with self.assertRaises(WebhookVerificationError) as raised:
                verify_webhook_signature(**args)
            self.assertEqual(raised.exception.code, code)

    def test_construct_event_reads_headers_case_insensitively(self):
        headers = {"Prooftask-Timestamp": TS, "Prooftask-Signature": SIGNATURE, "Prooftask-Event-Id": "evt", "Prooftask-Delivery-Id": "d"}
        hook = construct_webhook_event(SECRET, BODY, headers, now=NOW)
        self.assertEqual((hook.event_id, hook.delivery_id, hook.is_test, hook.event["type"]), ("evt", "d", False, "agreement.confirmed"))


class ClientTests(unittest.TestCase):
    def test_request_ids_and_pagination(self):
        saved = with_request_id({"target": "x"})
        self.assertIs(with_request_id(saved), saved)
        self.assertEqual(request_id_of({"input": {"requestId": saved["requestId"]}}), saved["requestId"])
        pages = iter([{"rows": [1], "next": "b"}, {"rows": [2], "next": None}])
        asked = []
        rows = [r for page in paginate(lambda after: (asked.append(after), next(pages))[1]) for r in page["rows"]]
        self.assertEqual((rows, asked), ([1, 2], [None, "b"]))

    def test_every_operation_has_a_method(self):
        client = ProofTaskClient(origin="https://prooftask.example")
        for operation_id in prooftask.OPERATIONS:
            snake = "".join("_" + c.lower() if c.isupper() else c for c in operation_id).lstrip("_")
            self.assertTrue(callable(getattr(client, snake)), operation_id)
        self.assertEqual(client.url("getProject", {"id": "delivery_a/b"}), "https://prooftask.example/api/agents/v1/projects/delivery_a%2Fb")
        self.assertEqual(client.url("getCreationDocuments", {}), "https://prooftask.example/api/acceptance/legal-config")
        with self.assertRaises(ValueError):
            ProofTaskClient(origin="http://prooftask.example")

    def test_typed_error(self):
        import io
        import urllib.error
        error = urllib.error.HTTPError("https://prooftask.example/api/agents/v1/me", 409, "Conflict", {}, io.BytesIO(json.dumps({"error": "REQUEST_CONFLICT", "nextAction": "REUSE_OR_CHANGE_REQUEST_ID"}).encode()))
        client = ProofTaskClient(token="ptag_test", origin="https://prooftask.example", max_retries=0)
        with mock.patch.object(client._opener, "open", side_effect=error):
            with self.assertRaises(ConflictError) as raised:
                client.get_agent()
        self.assertEqual((raised.exception.code, raised.exception.next_action, raised.exception.status), ("REQUEST_CONFLICT", "REUSE_OR_CHANGE_REQUEST_ID", 409))


if __name__ == "__main__":
    unittest.main()
