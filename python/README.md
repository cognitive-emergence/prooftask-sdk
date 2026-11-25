# ProofTask SDK for Python

```sh
pip install prooftask
```

ProofTask keeps verifiable acceptance records: the agreed criteria, the exact delivered versions and the buyer's explicit
decision, signed by the issuer and checkable offline. [What a verifiable acceptance record is](https://prooftask.com/developers/verifiable-acceptance) ·
[Developer documentation](https://prooftask.com/developers) · [Sandbox](https://prooftask.com/developers/sandbox)

A client for the [Agent API](https://prooftask.com/api/agents/v1/openapi.json), generated from its OpenAPI contract, plus
webhook signature verification, idempotent request IDs, pagination and typed errors.
Standard library only, Python 3.9 or later.

**Offline record verification: `prooftask.conformity`.** An independent verifier for Conformity 1.0, 1.1 and 1.2
records, written from the [published specification](https://github.com/cognitive-emergence/tsto-spec/tree/main/conformity)
and [the implementer's guide](https://prooftask.com/developers/conformity-verifier.md), not ported from the JavaScript
verifier. It passes the whole
[conformance suite](https://github.com/cognitive-emergence/tsto-spec/tree/main/conformity/conformance/conformity-1). Ed25519 verification is a pure-Python
RFC 8032 implementation tested against the RFC vectors, so the package stays dependency-free.

```python
from prooftask.conformity import verify_record
report = verify_record(open("record.json", "rb").read(), {"issuers": {"https://issuer.example": [
    {"id": "key-1", "publicKeyPem": PEM, "status": "ACTIVE"}]}})
print(report["status"], report["reasons"])   # INVALID, INDETERMINATE, PARTIAL_DISCLOSURE or VERIFIED_WITH_LIMITATIONS
```

or `python -m prooftask.conformity ARTIFACT TRUST [OPTIONS.json]` (exit 0 verified, 1 INVALID, 3 INDETERMINATE, 2 usage).
You supply the trusted issuer keys. Package verification checks RFC 3161 tokens and OpenTimestamps proofs offline
against the bundled Sectigo root and Bitcoin checkpoint. You can supply your own `anchor_trust` (CLI option
`anchorTrust`) with `timeStampRoots`, `bitcoin` and optional `timeStampPolicyOids`. ECDSA timestamp signatures
use the system `openssl dgst` command. RSA timestamps and Bitcoin proofs use Python's standard library.

Typed event evidence identifies each signed event and checks its chain prefix. Each event reports its recorder time
separately from the independent upper bound, which includes the token's accuracy and requires revocation coverage.
The assurance label describes the service declared by the package supplier. Use the [Node.js verifier](https://prooftask.com/developers/verify-conformity.mjs)
for the ProofTask product record wrapper (`prooftask-result-record-*.json`, with the product trust bundle).

## Quickstart

```python
from prooftask import ProofTaskClient, new_request_id, construct_webhook_event

client = ProofTaskClient(token=os.environ["PROOFTASK_AGENT_TOKEN"])
me = client.get_agent()
project = client.get_project(id="delivery_...")["project"]

# Save the whole body (with its request ID) before sending. After an uncertain result, resend it unchanged.
body = {"requestId": new_request_id(), "target": "https://example.com/hooks/prooftask", "projectIds": [project["taskId"]],
        "eventTypes": ["acceptance.decided"], "expiresAt": "2026-12-20T00:00:00.000Z", "confirmed": True}
created = client.create_project_webhook(body=body)
```

`examples/quickstart.py` also runs a receiver and verifies a signed test request. The repository's test suite runs it
against a local ProofTask server.

## Methods

Every operation is a method named after its `operationId` in snake_case, with keyword arguments: path and query
parameters in snake_case (`subscription_id`, `project_id`) and the JSON request `body`. Request and response shapes are
`TypedDict`s in `prooftask.types`.

## Retries, pagination, errors

- Network failures, timeouts, 429 and 503 are retried (two retries by default). A write is retried only when its body
  carries a `requestId`, with the exact same bytes. `ProofTaskTransportError.outcome_unknown` means: resend the saved body.
- `client.iterate_webhook_deliveries(subscription_id=...)` yields every page and follows `next`; `paginate()` is generic.
- Non-success answers raise `BadRequestError`, `AuthenticationError`, `PermissionDeniedError`, `NotFoundError`,
  `ConflictError`, `RateLimitError` or `ServiceUnavailableError`, all `ProofTaskApiError` with `status`, `code`,
  `next_action`, `field`, `detail`, `reason` and `human_url`.

## Webhooks

```python
hook = construct_webhook_event(secret, raw_body, request_headers)  # raises WebhookVerificationError
if hook.is_test:
    return  # acknowledge test requests, do not act on them
```

Pass the exact raw body bytes. The signature is `v1=` + hex HMAC-SHA256 of `timestamp + "." + raw body`, compared with
`hmac.compare_digest`; the timestamp must be within five minutes.

## Development

Source: [cognitive-emergence/prooftask-sdk](https://github.com/cognitive-emergence/prooftask-sdk/tree/main/python),
a read-only copy synced from ProofTask's main repository. `src/prooftask/_generated_*.py` are generated from the Agent
API contract; never edit them. `python3 -I tests/test_sdk.py` and `python3 -I tests/test_conformity.py` run the unit
tests. Report problems through [ProofTask support](https://prooftask.com/support).

## Changelog

- **0.1.1**: the source is public at cognitive-emergence/prooftask-sdk, and the project's `Source` URL points there.
  Updated README and project metadata; the unit tests also run outside the ProofTask repository. No API change.
- **0.1.0**: first release.

## License

Apache License, Version 2.0. See [`LICENSE`](LICENSE). Only the SDKs and the offline verifier are open source; the ProofTask service is proprietary.
