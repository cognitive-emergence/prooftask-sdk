# ProofTask SDK for TypeScript and JavaScript

```sh
npm install @prooftask/sdk
```

ProofTask keeps verifiable acceptance records: the agreed criteria, the exact delivered versions and the buyer's explicit
decision, signed by the issuer and checkable offline. [What a verifiable acceptance record is](https://prooftask.com/developers/verifiable-acceptance) ·
[Developer documentation](https://prooftask.com/developers) · [Sandbox](https://prooftask.com/developers/sandbox)

A client for the [Agent API](https://prooftask.com/api/agents/v1/openapi.json), generated from its OpenAPI contract, plus:

- webhook signature verification exactly as [project events](https://prooftask.com/developers/project-events.md) specify;
- idempotent request IDs;
- cursor pagination;
- typed errors;
- offline record verification with the published verifier (`verify-conformity.mjs`), run in a sandboxed child process.

No runtime dependencies. Node.js 22.13 or later.

## Quickstart

```ts
import { ProofTaskClient, newRequestId, constructWebhookEvent } from '@prooftask/sdk';

const client = new ProofTaskClient({ token: process.env.PROOFTASK_AGENT_TOKEN });
const me = await client.getAgent();
const { project } = await client.getProject({ id: 'delivery_…' });

// Save the whole body (with its request ID) before sending. After an uncertain result, resend it unchanged.
const body = { requestId: newRequestId(), target: 'https://example.com/hooks/prooftask', projectIds: [project.taskId],
  eventTypes: ['acceptance.decided'], expiresAt: '2026-12-20T00:00:00.000Z', confirmed: true } as const;
const { subscription, secret } = await client.createProjectWebhook({ body });
```

A complete example that also runs a receiver and verifies a signed test request is in `examples/quickstart.ts`.
The repository's test suite runs it against a local ProofTask server.

## Methods

Every operation of the contract is a method named after its `operationId` in camelCase. Methods take one object:
path and query parameters by name, and the JSON request body as `body`. For example
`client.submitMaterials({ id, body })`, `client.listWebhookDeliveries({ subscriptionId, after })`.
Public bootstrap operations (`getCreationDocuments`, `previewOperationConfirmation`, `getAgentCapabilities`,
the connection flow) never receive the credential.

Types for every request and response schema are exported (`ProjectView`, `WebhookCreate`, …).

## Retries and request IDs

The client retries network failures, timeouts, 429 and 503 (two retries by default, honoring `retry-after` up to 60 seconds).
It retries a write only when its body carries a `requestId` (or `input.requestId` for project commands), and it resends
the exact same bytes. A write that still has no answer throws `ProofTaskTransportError` with `outcomeUnknown: true`:
resend the saved body with the same request ID. `newRequestId()` and `withRequestId(body)` create IDs.

## Pagination

`client.iterateWebhookDeliveries({ subscriptionId })` yields every page and follows `next` until it is `null`.
Pass `after` to resume from a saved checkpoint. `paginate()` and `rows()` are the generic helpers.

## Errors

Non-success answers throw a subclass of `ProofTaskApiError`: `BadRequestError` (400, 413), `AuthenticationError` (401),
`PermissionDeniedError` (403), `NotFoundError` (404), `ConflictError` (409), `RateLimitError` (429) or
`ServiceUnavailableError` (5xx). Each carries `status`, the stable `code`, and `nextAction`, `field`, `detail`,
`reason` and `humanUrl` when the server sent them.

## Webhooks

```ts
const hook = constructWebhookEvent({ secret, rawBody, headers: req.headers }); // throws WebhookVerificationError
if (hook.isTest) return; // acknowledge test requests, do not act on them
```

Pass the exact raw body bytes, before any JSON parsing. The signature is `v1=` + hex HMAC-SHA256 of
`timestamp + "." + raw body`; it is compared in constant time and the timestamp must be within five minutes.
A valid signature is not current authority: read the project before acting, and deduplicate by `eventId`.

## Offline record verification

```ts
import { verifyRecordOffline } from '@prooftask/sdk';
const { outcome, report } = await verifyRecordOffline({ record: savedRecordFile, trust: trustBundle });
```

This runs the published `verify-conformity.mjs` (shipped in `verifier/`) in a child process that can read only the
verifier and a temporary directory with your files. It makes no network requests. Without `trust`, the record's keys are
accepted only when they match the ProofTask keys pinned in the verifier. Read `report.reasons`: they name what the check
did not prove.

## Development

Source: [cognitive-emergence/prooftask-sdk](https://github.com/cognitive-emergence/prooftask-sdk/tree/main/typescript),
a read-only copy synced from ProofTask's main repository. The files in `src/generated/` are generated from the Agent API
contract; never edit them. `npm run typecheck` checks the source; `npm pack` builds `dist/` and copies the offline verifier.
Report problems through [ProofTask support](https://prooftask.com/support).

## Changelog

- **0.1.1**: the source is public at cognitive-emergence/prooftask-sdk, and the package's `repository` points there.
  Updated README and package metadata. No API change.
- **0.1.0**: first release.

## License

Apache License, Version 2.0. See [`LICENSE`](LICENSE). Only the SDKs and the offline verifier are open source; the ProofTask service is proprietary.
