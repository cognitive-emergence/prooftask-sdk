"""ProofTask Python SDK quickstart.

  PROOFTASK_AGENT_TOKEN       Agent credential whose project scope includes PROOFTASK_PROJECT_ID
  PROOFTASK_PROJECT_ID        delivery_... project to read and subscribe to
  PROOFTASK_WEBHOOK_TARGET    public HTTPS URL that forwards to this machine's RECEIVER_PORT (for example a tunnel)
  PROOFTASK_ORIGIN            optional, default https://prooftask.com
  RECEIVER_PORT               optional local port of the webhook receiver, default 8787

It reads the agent and the project, creates a project-scoped webhook subscription (with an idempotent request ID),
reads it back, asks ProofTask to send a signed test request, verifies that request's signature and prints a summary.
"""
import json
import os
import sys
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))  # not needed once installed

from prooftask import PermissionDeniedError, ProofTaskClient, WebhookVerificationError, construct_webhook_event, new_request_id  # noqa: E402

client = ProofTaskClient(token=os.environ["PROOFTASK_AGENT_TOKEN"], origin=os.environ.get("PROOFTASK_ORIGIN", "https://prooftask.com"))
project_id = os.environ["PROOFTASK_PROJECT_ID"]

agent = client.get_agent()
project = client.get_project(id=project_id)["project"]

secret = ""
received = []


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("content-length", "0")))
        try:
            hook = construct_webhook_event(secret, raw, self.headers)  # exact raw bytes, before parsing
            received.append({"verified": True, "isTest": hook.is_test, "eventId": hook.event_id})
            self.send_response(204)
        except WebhookVerificationError as error:
            received.append({"verified": False, "error": error.code})
            self.send_response(400)
        self.end_headers()

    def log_message(self, *args: object) -> None:
        pass


server = HTTPServer(("127.0.0.1", int(os.environ.get("RECEIVER_PORT", "8787"))), Receiver)
threading.Thread(target=server.serve_forever, daemon=True).start()
try:
    # Save this body (with its request ID) before sending; resend it unchanged after an uncertain result.
    expires = (datetime.now(timezone.utc) + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.") + "000Z"
    request = {"requestId": new_request_id(), "target": os.environ["PROOFTASK_WEBHOOK_TARGET"], "projectIds": [project_id],
               "eventTypes": ["agreement.confirmed", "delivery.submitted", "acceptance.decided"], "expiresAt": expires, "confirmed": True}
    created = client.create_project_webhook(body=request)
    secret = created.get("secret", "")
    replay = client.create_project_webhook(body=request)  # same request ID and body: replayed, the secret is not shown again
    subscription = next(s for s in client.list_project_webhooks() if s["id"] == created["subscription"]["id"])

    test = client.test_project_webhook(subscription_id=created["subscription"]["id"], body={})
    deliveries = sum(len(page["rows"]) for page in client.iterate_webhook_deliveries(subscription_id=created["subscription"]["id"]))

    missing = ""
    try:
        client.get_project(id="delivery_00000000-0000-4000-8000-000000000000")
    except PermissionDeniedError as error:  # outside this credential's project scope
        missing = error.code

    print(json.dumps({
        "agent": {"id": agent["id"], "organizationId": agent["organizationId"]},
        "project": {"taskId": project["taskId"], "state": project["state"]},
        "subscription": {"id": created["subscription"]["id"], "projectIds": subscription["projectIds"],
                         "secretShownOnce": bool(created.get("secret")) and not replay.get("secret")},
        "test": {"outcome": test["outcome"], "status": test["status"]},
        "received": received, "deliveries": deliveries, "typedError": missing,
    }, indent=1))
finally:
    server.shutdown()
