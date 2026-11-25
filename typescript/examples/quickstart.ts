// ProofTask TypeScript SDK quickstart.
//   PROOFTASK_AGENT_TOKEN       Agent credential whose project scope includes PROOFTASK_PROJECT_ID
//   PROOFTASK_PROJECT_ID        delivery_… project to read and subscribe to
//   PROOFTASK_WEBHOOK_TARGET    public HTTPS URL that forwards to this machine's RECEIVER_PORT (for example a tunnel)
//   PROOFTASK_ORIGIN            optional, default https://prooftask.com
//   RECEIVER_PORT               optional local port of the webhook receiver, default 8787
// It reads the agent and the project, creates a project-scoped webhook subscription (with an idempotent request ID),
// reads it back, asks ProofTask to send a signed test request, verifies that request's signature and prints a summary.
// In your own code import from '@prooftask/sdk' instead of '../src/index.ts'.
import { createServer } from 'node:http';
import { once } from 'node:events';
import { ProofTaskClient, constructWebhookEvent, newRequestId, PermissionDeniedError, WebhookVerificationError, type WebhookCreate } from '../src/index.ts';

const env = (name: string) => { const value = process.env[name]; if (!value) throw new Error(name + ' is required'); return value; };
const client = new ProofTaskClient({ ...(process.env.PROOFTASK_ORIGIN ? { origin: process.env.PROOFTASK_ORIGIN } : {}), token: env('PROOFTASK_AGENT_TOKEN') });
const projectId = env('PROOFTASK_PROJECT_ID');

const agent = await client.getAgent();
const { project } = await client.getProject({ id: projectId });

// Receiver: verify the exact raw bytes before parsing anything.
let secret = '';
const received: Array<{ verified: boolean; isTest?: boolean; eventId?: string; error?: string }> = [];
const receiver = createServer((req, res) => {
  const chunks: Buffer[] = [];
  req.on('data', chunk => chunks.push(chunk));
  req.on('end', () => {
    try {
      const hook = constructWebhookEvent({ secret, rawBody: Buffer.concat(chunks), headers: req.headers });
      received.push({ verified: true, isTest: hook.isTest, eventId: hook.eventId });
      res.writeHead(204).end();
    } catch (error) {
      received.push({ verified: false, error: error instanceof WebhookVerificationError ? error.code : String(error) });
      res.writeHead(400).end();
    }
  });
});
receiver.listen(Number(process.env.RECEIVER_PORT ?? 8787), '127.0.0.1');
await once(receiver, 'listening');

try {
  // Save this body (with its request ID) before sending; resend it unchanged after an uncertain result.
  const request: WebhookCreate = {
    requestId: newRequestId(), target: env('PROOFTASK_WEBHOOK_TARGET'), projectIds: [projectId],
    eventTypes: ['agreement.confirmed', 'delivery.submitted', 'acceptance.decided'],
    expiresAt: new Date(Date.now() + 7 * 86400000).toISOString(), confirmed: true,
  };
  const created = await client.createProjectWebhook({ body: request });
  secret = created.secret ?? '';
  const replay = await client.createProjectWebhook({ body: request }); // same request ID and body: replayed, the secret is not shown again
  const subscription = (await client.listProjectWebhooks()).find(s => s.id === created.subscription.id);

  const test = await client.testProjectWebhook({ subscriptionId: created.subscription.id, body: {} });
  let deliveries = 0;
  for await (const page of client.iterateWebhookDeliveries({ subscriptionId: created.subscription.id })) deliveries += page.rows.length;

  let missing = '';
  try { await client.getProject({ id: 'delivery_00000000-0000-4000-8000-000000000000' }); }
  catch (error) { if (error instanceof PermissionDeniedError) missing = error.code; else throw error; } // outside this credential's project scope

  console.log(JSON.stringify({
    agent: { id: agent.id, organizationId: agent.organizationId },
    project: { taskId: project.taskId, state: project.state },
    subscription: { id: created.subscription.id, projectIds: subscription?.projectIds, secretShownOnce: Boolean(created.secret) && !replay.secret },
    test: { outcome: test.outcome, status: test.status },
    received, deliveries, typedError: missing,
  }, null, 1));
} finally {
  receiver.close();
}
