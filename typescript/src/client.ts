/** The Agent API client: generated operation methods over a small hand-written transport. */
import { GeneratedOperations, OPERATIONS, API_BASE_PATH, type OperationArgs, type OperationResults } from './generated/operations.ts';
import type { OperationSpec, Page, RequestOptions } from './core.ts';
import { apiError, ProofTaskTransportError, type ApiErrorBody } from './errors.ts';
import { requestIdOf } from './request-id.ts';
import { paginate } from './pagination.ts';

export const SDK_VERSION = '0.1.4';
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]']);

export interface ClientOptions {
  /** Service origin. Defaults to https://prooftask.com. Plain http is accepted only for a loopback test server. */
  origin?: string;
  /** Agent credential (ptag_…) issued by a person in /agents. Never sent to public bootstrap operations. */
  token?: string;
  /** Request timeout in milliseconds (default 30000). */
  timeoutMs?: number;
  /** Retries after a network failure, a timeout, 429 or 503 (default 2). Writes are retried only when their body carries a requestId. */
  maxRetries?: number;
  /** Replaces the global fetch, for example to add a proxy. */
  fetch?: typeof fetch;
  /** Appended to the user-agent header. */
  userAgent?: string;
}

function checkedOrigin(value: string): string {
  const url = new URL(value);
  if (url.pathname !== '/' || url.search || url.hash || url.username || url.password) throw new TypeError('origin must be a bare origin such as https://prooftask.com');
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && LOOPBACK.has(url.hostname))) throw new TypeError('origin must use https (http is accepted only for a loopback test server)');
  return url.origin;
}
const sleep = (ms: number, signal?: AbortSignal) => new Promise<void>((resolve, reject) => {
  const timer = setTimeout(resolve, ms);
  signal?.addEventListener('abort', () => { clearTimeout(timer); reject(signal.reason); }, { once: true });
});

export class ProofTaskClient extends GeneratedOperations {
  readonly origin: string;
  readonly #token: string | undefined;
  readonly #timeoutMs: number;
  readonly #maxRetries: number;
  readonly #fetch: typeof fetch;
  readonly #userAgent: string;

  constructor(options: ClientOptions = {}) {
    super();
    this.origin = checkedOrigin(options.origin ?? 'https://prooftask.com');
    if (options.token !== undefined && !/^\S{1,4096}$/.test(options.token)) throw new TypeError('token must be a non-empty string without spaces');
    this.#token = options.token;
    this.#timeoutMs = options.timeoutMs ?? 30000;
    this.#maxRetries = options.maxRetries ?? 2;
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#userAgent = `prooftask-sdk-typescript/${SDK_VERSION}${options.userAgent ? ' ' + options.userAgent : ''}`;
  }

  /** The Agent API base URL, for example https://prooftask.com/api/agents/v1. */
  get apiBaseUrl(): string { return this.origin + API_BASE_PATH; }

  /** Builds the request URL for an operation from its arguments. */
  url<K extends keyof OperationArgs>(operation: K, args: OperationArgs[K]): string {
    const spec: OperationSpec = OPERATIONS[operation], values = args as Record<string, unknown>;
    const path = spec.path.replace(/\{([^}]+)\}/g, (_, name: string) => {
      const value = values[name];
      if (typeof value !== 'string' || !value) throw new TypeError(`${spec.operationId}: path parameter ${name} is required`);
      return encodeURIComponent(value);
    });
    const url = new URL(this.origin + spec.basePath + path);
    for (const name of spec.queryParams) { const value = values[name]; if (value !== undefined && value !== null) url.searchParams.set(name, String(value)); }
    return url.toString();
  }

  protected async call<K extends keyof OperationArgs>(operation: K, args: OperationArgs[K], options: RequestOptions = {}): Promise<OperationResults[K]> {
    const spec: OperationSpec = OPERATIONS[operation], url = this.url(operation, args);
    const body = (args as { body?: unknown }).body;
    if (spec.body === 'required' && body === undefined) throw new TypeError(`${spec.operationId}: body is required`);
    // Serialize once: a retry resends exactly these bytes.
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const headers: Record<string, string> = { accept: 'application/json', 'user-agent': this.#userAgent };
    if (payload !== undefined) headers['content-type'] = 'application/json';
    if (spec.auth) {
      if (!this.#token) throw new TypeError(`${spec.operationId} needs an Agent credential: pass token to ProofTaskClient`);
      headers.authorization = 'Bearer ' + this.#token;
    }
    const replayable = spec.method === 'GET' || requestIdOf(body) !== undefined;
    const retries = replayable ? options.maxRetries ?? this.#maxRetries : 0;
    for (let attempt = 0; ; attempt++) {
      let response: Response;
      try {
        const signals = [AbortSignal.timeout(options.timeoutMs ?? this.#timeoutMs), ...(options.signal ? [options.signal] : [])];
        response = await this.#fetch(url, { method: spec.method, headers, ...(payload !== undefined ? { body: payload } : {}), redirect: 'error', signal: AbortSignal.any(signals) });
      } catch (error) {
        if (options.signal?.aborted) throw error;
        if (attempt < retries) { await sleep(500 * 2 ** attempt, options.signal); continue; }
        throw new ProofTaskTransportError(spec.operationId, spec.method !== 'GET', error);
      }
      const text = await response.text().catch(() => undefined);
      if (response.ok) {
        if (text === undefined) throw new ProofTaskTransportError(spec.operationId, spec.method !== 'GET', new Error('UNREADABLE_BODY'));
        try { return (text === '' ? undefined : JSON.parse(text)) as OperationResults[K]; }
        catch (error) { throw new ProofTaskTransportError(spec.operationId, spec.method !== 'GET', error); }
      }
      const retryAfterHeader = response.headers.get('retry-after'), retryAfter = retryAfterHeader && /^\d{1,6}$/.test(retryAfterHeader) ? Number(retryAfterHeader) : undefined;
      if ((response.status === 429 || response.status === 503) && attempt < retries && (retryAfter ?? 0) <= 60) {
        await sleep(retryAfter !== undefined ? retryAfter * 1000 : 500 * 2 ** attempt, options.signal); continue;
      }
      let parsed: ApiErrorBody | string | undefined = text;
      try { if (text) parsed = JSON.parse(text) as ApiErrorBody; } catch { /* keep the text */ }
      throw apiError(spec.operationId, response.status, parsed, retryAfter);
    }
  }

  protected pages<K extends keyof OperationArgs, R>(operation: K, args: OperationArgs[K], options?: RequestOptions): AsyncGenerator<Page<R>> {
    const first = (args as { after?: string }).after;
    return paginate<R>(after => this.call(operation, { ...args, after } as OperationArgs[K], options) as Promise<unknown> as Promise<Page<R>>, first);
  }
}
