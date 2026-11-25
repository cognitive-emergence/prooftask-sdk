/** Typed errors. Branch on `code` (the API's stable error code) or on the class. */

export class ProofTaskError extends Error {
  constructor(message: string) { super(message); this.name = new.target.name; }
}

/** Fields of the API's error body (components.schemas.Error). */
export interface ApiErrorBody {
  error?: string;
  nextAction?: string;
  reason?: string;
  field?: string;
  detail?: string;
  humanUrl?: string;
  documentationUrl?: string;
  requiredHumanAction?: string;
  [key: string]: unknown;
}

/** The server answered with a non-success HTTP status. */
export class ProofTaskApiError extends ProofTaskError {
  readonly status: number;
  /** Stable error code from the body's `error` field (for example `WEBHOOK_REQUEST_INVALID`), or `HTTP_<status>`. */
  readonly code: string;
  /** What the API says to do next, for example `CORRECT_REQUEST_AND_RETRY` or `WAIT_FOR_HUMAN`. */
  readonly nextAction: string | undefined;
  /** JSON pointer to the failing request field on a 400 response. */
  readonly field: string | undefined;
  readonly detail: string | undefined;
  readonly reason: string | undefined;
  readonly humanUrl: string | undefined;
  /** Seconds from the `retry-after` header, when present. */
  readonly retryAfter: number | undefined;
  readonly body: ApiErrorBody | string | undefined;
  readonly operationId: string;
  constructor(operationId: string, status: number, body: ApiErrorBody | string | undefined, retryAfter: number | undefined) {
    const parsed = typeof body === 'object' && body !== null ? body : {};
    const code = typeof parsed.error === 'string' ? parsed.error : `HTTP_${status}`;
    super(`${operationId} failed with HTTP ${status}: ${code}${typeof parsed.detail === 'string' ? ` (${parsed.detail})` : typeof parsed.reason === 'string' ? ` (${parsed.reason})` : ''}`);
    this.operationId = operationId; this.status = status; this.code = code; this.body = body; this.retryAfter = retryAfter;
    this.nextAction = typeof parsed.nextAction === 'string' ? parsed.nextAction : undefined;
    this.field = typeof parsed.field === 'string' ? parsed.field : undefined;
    this.detail = typeof parsed.detail === 'string' ? parsed.detail : undefined;
    this.reason = typeof parsed.reason === 'string' ? parsed.reason : undefined;
    this.humanUrl = typeof parsed.humanUrl === 'string' ? parsed.humanUrl : undefined;
  }
}
/** 400 or 413: the request is malformed, too large or fails validation. Fix the field named in `field`. */
export class BadRequestError extends ProofTaskApiError {}
/** 401: the credential is missing, expired or revoked. */
export class AuthenticationError extends ProofTaskApiError {}
/** 403: the credential is valid but its authority does not cover this action. */
export class PermissionDeniedError extends ProofTaskApiError {}
/** 404: not found, or not visible to this credential. */
export class NotFoundError extends ProofTaskApiError {}
/** 409: stale expected state, a request ID reused with different content, or a state that does not allow the action. */
export class ConflictError extends ProofTaskApiError {}
/** 429: rate limited. `retryAfter` gives the wait in seconds when the server sent one. */
export class RateLimitError extends ProofTaskApiError {}
/** 5xx: the service could not answer. */
export class ServiceUnavailableError extends ProofTaskApiError {}

export function apiError(operationId: string, status: number, body: ApiErrorBody | string | undefined, retryAfter: number | undefined): ProofTaskApiError {
  const Kind = status === 400 || status === 413 ? BadRequestError : status === 401 ? AuthenticationError : status === 403 ? PermissionDeniedError
    : status === 404 ? NotFoundError : status === 409 ? ConflictError : status === 429 ? RateLimitError : status >= 500 ? ServiceUnavailableError : ProofTaskApiError;
  return new Kind(operationId, status, body, retryAfter);
}

/** No usable HTTP answer (network failure, timeout or unreadable body).
 * For a write, `outcomeUnknown` is true: the server may have applied it. Resend the exact same body with the same requestId. */
export class ProofTaskTransportError extends ProofTaskError {
  readonly operationId: string;
  readonly outcomeUnknown: boolean;
  constructor(operationId: string, outcomeUnknown: boolean, cause: unknown) {
    super(`${operationId}: no usable response${outcomeUnknown ? '; the outcome is unknown, resend the same body with the same requestId' : ''}`);
    this.operationId = operationId; this.outcomeUnknown = outcomeUnknown; this.cause = cause;
  }
}

/** A webhook request failed signature or freshness checks. Do not act on its body. */
export class WebhookVerificationError extends ProofTaskError {
  readonly code: 'MISSING_HEADER' | 'TIMESTAMP_INVALID' | 'TIMESTAMP_OUT_OF_TOLERANCE' | 'SIGNATURE_FORMAT_INVALID' | 'SIGNATURE_MISMATCH' | 'BODY_NOT_JSON';
  constructor(code: WebhookVerificationError['code'], message: string) { super(message); this.code = code; }
}

/** The offline verifier could not run or could not read its input (not a verdict: verdicts are returned, not thrown). */
export class OfflineVerificationError extends ProofTaskError {
  readonly exitCode: number | null;
  readonly stderr: string;
  constructor(message: string, exitCode: number | null, stderr: string) { super(message); this.exitCode = exitCode; this.stderr = stderr; }
}
