/** Idempotent request IDs.
 * Every Agent API write carries a version 4 UUID `requestId` (in the body, or in `input` for project commands).
 * The server replays the same answer for the same ID and body, and rejects different content under that ID.
 * Generate the ID once, save the complete body before sending, and resend that exact body after an uncertain result. */
import { randomUUID } from 'node:crypto';

const UUID_V4 = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;

/** A fresh lowercase version 4 UUID. */
export function newRequestId(): string { return randomUUID(); }

export function isRequestId(value: unknown): value is string { return typeof value === 'string' && UUID_V4.test(value); }

/** The body with a `requestId`: the existing one is kept, so calling this again on a saved body never changes it. */
export function withRequestId<B extends Record<string, unknown>>(body: B): B & { requestId: string } {
  if (body.requestId !== undefined && !isRequestId(body.requestId)) throw new TypeError('requestId must be a lowercase version 4 UUID');
  return (body.requestId === undefined ? { ...body, requestId: newRequestId() } : body) as B & { requestId: string };
}

/** The request ID a body carries (`requestId`, or `input.requestId` for project command envelopes), if any. */
export function requestIdOf(body: unknown): string | undefined {
  if (!body || typeof body !== 'object') return undefined;
  const b = body as { requestId?: unknown; input?: { requestId?: unknown } };
  if (isRequestId(b.requestId)) return b.requestId;
  if (b.input && typeof b.input === 'object' && isRequestId(b.input.requestId)) return b.input.requestId;
  return undefined;
}
