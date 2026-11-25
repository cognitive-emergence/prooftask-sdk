/** Webhook signature verification, as docs/developers/PROJECT_EVENTS.md specifies:
 * - `prooftask-signature` is `v1=` followed by the lowercase hex HMAC-SHA256 of `timestamp + "." + raw body`, keyed by the subscription secret;
 * - `prooftask-timestamp` is the attempt time in Unix seconds; reject it when more than five minutes away from now;
 * - compare in constant time, and verify the exact raw bytes before parsing JSON.
 * A valid signature proves the request came from ProofTask for this subscription. It is not current project authority:
 * read the current project state before acting, and deduplicate by `prooftask-event-id` (retries repeat events). */
import { createHmac, timingSafeEqual } from 'node:crypto';
import { WebhookVerificationError } from './errors.ts';

export const SIGNATURE_HEADER = 'prooftask-signature';
export const TIMESTAMP_HEADER = 'prooftask-timestamp';
export const EVENT_ID_HEADER = 'prooftask-event-id';
export const DELIVERY_ID_HEADER = 'prooftask-delivery-id';
/** Five minutes, the documented freshness window. */
export const DEFAULT_TOLERANCE_SECONDS = 300;

type Bytes = string | Uint8Array;
const bytes = (value: Bytes) => typeof value === 'string' ? Buffer.from(value, 'utf8') : Buffer.from(value.buffer, value.byteOffset, value.byteLength);

/** The `v1=` signature ProofTask sends for these bytes. Useful to test a receiver. */
export function signWebhookPayload(secret: string, timestamp: string, rawBody: Bytes): string {
  return 'v1=' + createHmac('sha256', secret).update(Buffer.concat([Buffer.from(timestamp + '.', 'utf8'), bytes(rawBody)])).digest('hex');
}

export interface VerifyWebhookInput {
  /** The subscription's signing secret, returned once on create or rotate-secret. */
  secret: string;
  /** The exact request body bytes, before any JSON parsing or re-encoding. */
  rawBody: Bytes;
  /** The `prooftask-timestamp` header. */
  timestamp: string | null | undefined;
  /** The `prooftask-signature` header. */
  signature: string | null | undefined;
  /** Current time in milliseconds (default Date.now()). */
  now?: number;
  /** Freshness window in seconds (default 300). */
  toleranceSeconds?: number;
}

/** Throws WebhookVerificationError unless the signature and timestamp are valid. */
export function verifyWebhookSignature(input: VerifyWebhookInput): void {
  const { secret, rawBody, timestamp, signature } = input;
  if (typeof secret !== 'string' || !secret) throw new TypeError('secret is required');
  if (typeof timestamp !== 'string' || !timestamp) throw new WebhookVerificationError('MISSING_HEADER', 'Missing prooftask-timestamp header');
  if (typeof signature !== 'string' || !signature) throw new WebhookVerificationError('MISSING_HEADER', 'Missing prooftask-signature header');
  if (!/^\d{1,12}$/.test(timestamp)) throw new WebhookVerificationError('TIMESTAMP_INVALID', 'prooftask-timestamp must be Unix seconds');
  const tolerance = input.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS, now = input.now ?? Date.now();
  if (Math.abs(now - Number(timestamp) * 1000) > tolerance * 1000) throw new WebhookVerificationError('TIMESTAMP_OUT_OF_TOLERANCE', 'prooftask-timestamp is more than ' + tolerance + ' seconds from now');
  if (!/^v1=[a-f0-9]{64}$/.test(signature)) throw new WebhookVerificationError('SIGNATURE_FORMAT_INVALID', 'prooftask-signature must be v1= followed by 64 lowercase hex characters');
  const expected = Buffer.from(signWebhookPayload(secret, timestamp, rawBody).slice(3), 'hex'), given = Buffer.from(signature.slice(3), 'hex');
  if (!timingSafeEqual(expected, given)) throw new WebhookVerificationError('SIGNATURE_MISMATCH', 'Signature does not match this secret and body');
}

/** Header lookup over a Fetch `Headers`, a Node `IncomingHttpHeaders` or a plain object, case-insensitively. */
export type HeaderSource = Headers | Record<string, string | string[] | undefined>;
function header(headers: HeaderSource, name: string): string | undefined {
  if (typeof (headers as Headers).get === 'function') return (headers as Headers).get(name) ?? undefined;
  for (const [key, value] of Object.entries(headers as Record<string, string | string[] | undefined>))
    if (key.toLowerCase() === name) return Array.isArray(value) ? (value.length === 1 ? value[0] : undefined) : value;
  return undefined;
}

export interface VerifiedWebhook<E = Record<string, unknown>> {
  /** Stable event ID: deduplicate side effects with it. For a test request it is the `whtest_…` ID. */
  eventId: string;
  deliveryId: string;
  /** Attempt time in Unix seconds. */
  timestamp: number;
  /** True for a `POST /webhooks/{id}/test` request: acknowledge it and do not act on it. */
  isTest: boolean;
  /** The parsed body. */
  event: E;
}

/** Verifies a received request and returns its parsed body and identifiers. Throws WebhookVerificationError otherwise. */
export function constructWebhookEvent<E = Record<string, unknown>>(input: { secret: string; rawBody: Bytes; headers: HeaderSource; now?: number; toleranceSeconds?: number }): VerifiedWebhook<E> {
  const timestamp = header(input.headers, TIMESTAMP_HEADER), signature = header(input.headers, SIGNATURE_HEADER);
  verifyWebhookSignature({ secret: input.secret, rawBody: input.rawBody, timestamp, signature,
    ...(input.now !== undefined ? { now: input.now } : {}), ...(input.toleranceSeconds !== undefined ? { toleranceSeconds: input.toleranceSeconds } : {}) });
  const eventId = header(input.headers, EVENT_ID_HEADER), deliveryId = header(input.headers, DELIVERY_ID_HEADER);
  if (!eventId || !deliveryId) throw new WebhookVerificationError('MISSING_HEADER', 'Missing prooftask-event-id or prooftask-delivery-id header');
  let event: E;
  try { event = JSON.parse(bytes(input.rawBody).toString('utf8')) as E; } catch { throw new WebhookVerificationError('BODY_NOT_JSON', 'Body is not JSON'); }
  const type = (event as { type?: unknown } | null)?.type;
  return { eventId, deliveryId, timestamp: Number(timestamp), isTest: type === 'webhook.test', event };
}
