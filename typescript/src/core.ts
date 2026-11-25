/** Shapes shared by the generated operations and the hand-written client. */

/** One Agent API operation as listed in the generated OPERATIONS table. */
export interface OperationSpec {
  readonly operationId: string;
  readonly method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  /** Path below `basePath`, with `{name}` placeholders for path parameters. */
  readonly path: string;
  /** Path below the origin where this operation lives: the Agent API base, or "" for public bootstrap operations. */
  readonly basePath: string;
  /** Whether the operation takes the Agent bearer credential. Public operations never receive it. */
  readonly auth: boolean;
  readonly pathParams: readonly string[];
  readonly queryParams: readonly string[];
  readonly body: 'none' | 'required' | 'optional';
  readonly status: number;
}

/** Per-request settings. */
export interface RequestOptions {
  /** Abort the request (and any retry wait). */
  signal?: AbortSignal;
  /** Overrides the client's timeout for this request, in milliseconds. */
  timeoutMs?: number;
  /** Overrides the client's retry count for this request. 0 disables retries. */
  maxRetries?: number;
}

/** One page of a cursor-paginated list. `next` is null on the last page. */
export interface Page<Row> {
  rows: Row[];
  next: string | null;
  [key: string]: unknown;
}
