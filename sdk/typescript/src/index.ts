/**
 * IONA RPC Client — Production‑Grade
 *
 * Strongly‑typed HTTP client for the IONA node's JSON‑RPC and REST endpoints.
 *
 * @example
 * ```ts
 * const client = new IonaClient('http://127.0.0.1:9001', { apiKey: 'secret' });
 * const health = await client.health();
 * const status = await client.status();
 * ```
 */

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

/** Response from GET /health */
export type HealthResponse = string;

/** Response from GET /status */
export interface StatusResponse {
  height: number;
  peers: number;
  producing: boolean;
  version: string;
  chain_id: number;
  protocol_version: number;
  /** Unix timestamp of last committed block (seconds) */
  last_commit_time: number;
}

/** Response from GET /block?height=N (or /block/latest) */
export interface BlockResponse {
  height: number;
  hash: string;
  parent_hash: string;
  state_root: string;
  tx_root: string;
  timestamp: number;
  proposer: string;
  tx_count: number;
  gas_used: number;
}

/** Response from GET /tx/:hash */
export interface TxResponse {
  hash: string;
  height: number;
  from: string;
  to?: string;
  nonce: number;
  gas_limit: number;
  gas_used: number;
  success: boolean;
  payload: string;
  /** Hex‑encoded return data */
  data?: string;
}

/** Response from GET /validators */
export interface ValidatorResponse {
  total: number;
  total_power: number;
  validators: ValidatorInfo[];
}

export interface ValidatorInfo {
  pubkey: string;
  power: number;
  connected: boolean;
}

/** Error response shape from IONA RPC */
export interface IonaErrorBody {
  error: {
    code: string;
    message: string;
    request_id?: string;
  };
}

/** Options passed to the client constructor */
export interface ClientOptions {
  /** Request timeout in milliseconds (default: 5000) */
  timeoutMs?: number;
  /** Additional fetch options merged into every request */
  fetchOptions?: RequestInit;
  /** API key sent as Bearer token (optional) */
  apiKey?: string;
  /** Number of retries for idempotent GET requests (default: 0) */
  retries?: number;
  /** Base delay between retries in ms (exponential backoff, default: 300) */
  retryDelayMs?: number;
  /** Logger function (default: silent) */
  logger?: (level: 'info' | 'warn' | 'error', message: string, data?: unknown) => void;
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

export class IonaClientError extends Error {
  constructor(
    public readonly status?: number,
    message: string,
    public readonly originalError?: unknown,
  ) {
    super(message);
    this.name = 'IonaClientError';
  }
}

// -----------------------------------------------------------------------------
// Client
// -----------------------------------------------------------------------------

export class IonaClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchOptions: RequestInit;
  private readonly apiKey?: string;
  private readonly retries: number;
  private readonly retryDelayMs: number;
  private readonly logger: (level: 'info' | 'warn' | 'error', message: string, data?: unknown) => void;

  constructor(baseUrl: string, options: ClientOptions = {}) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.timeoutMs = options.timeoutMs ?? 5000;
    this.fetchOptions = options.fetchOptions ?? {};
    this.apiKey = options.apiKey;
    this.retries = options.retries ?? 0;
    this.retryDelayMs = options.retryDelayMs ?? 300;
    this.logger = options.logger ?? (() => {});
  }

  // ── Public methods ────────────────────────────────────────────────────────

  /** GET /health — plain‑text health status */
  async health(): Promise<HealthResponse> {
    return this.get<HealthResponse>('/health', { parse: 'text' });
  }

  /** GET /status — node status information */
  async status(): Promise<StatusResponse> {
    return this.get<StatusResponse>('/status');
  }

  /** GET /block/latest or /block?height=N */
  async block(height?: number): Promise<BlockResponse> {
    const path = height ? `/block?height=${height}` : '/block/latest';
    return this.get<BlockResponse>(path);
  }

  /** GET /tx/:hash */
  async tx(hash: string): Promise<TxResponse> {
    return this.get<TxResponse>(`/tx/${encodeURIComponent(hash)}`);
  }

  /** GET /validators */
  async validators(): Promise<ValidatorResponse> {
    return this.get<ValidatorResponse>('/validators');
  }

  /** POST /tx — submit a transaction (payload is the raw body string) */
  async submitTx(payload: string): Promise<{ hash: string }> {
    return this.post<{ hash: string }>('/tx', payload);
  }

  /** GET /peers */
  async peers(): Promise<string[]> {
    return this.get<string[]>('/peers');
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  /**
   * Perform a GET request with retry logic for transient failures.
   */
  private async get<T>(
    path: string,
    opts?: { parse?: 'json' | 'text' },
  ): Promise<T> {
    const parse = opts?.parse ?? 'json';
    const url = `${this.baseUrl}${path}`;

    let lastError: unknown;
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      try {
        const response = await this.fetchWithTimeout(url, {
          method: 'GET',
          headers: this.buildHeaders(),
        });

        if (!response.ok) {
          await this.handleErrorResponse(response);
        }

        if (parse === 'text') {
          return (await response.text()) as unknown as T;
        }
        return (await response.json()) as T;
      } catch (error) {
        lastError = error;
        if (error instanceof IonaClientError && error.status && error.status < 500) {
          // Don't retry client errors (4xx)
          throw error;
        }
        if (attempt < this.retries) {
          const delay = this.retryDelayMs * Math.pow(2, attempt);
          this.logger('warn', `Request to ${path} failed, retrying in ${delay}ms (attempt ${attempt + 1}/${this.retries})`, { error });
          await this.sleep(delay);
        }
      }
    }
    throw lastError;
  }

  /**
   * Perform a POST request (no retry — non‑idempotent).
   */
  private async post<T>(path: string, body: string): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithTimeout(url, {
      method: 'POST',
      headers: {
        ...this.buildHeaders(),
        'Content-Type': 'application/json',
      },
      body,
    });

    if (!response.ok) {
      await this.handleErrorResponse(response);
    }
    return (await response.json()) as T;
  }

  /**
   * Core fetch with AbortController timeout.
   */
  private async fetchWithTimeout(
    input: RequestInfo,
    init?: RequestInit,
  ): Promise<Response> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await fetch(input, {
        ...this.fetchOptions,
        ...init,
        signal: controller.signal,
      });
      return response;
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        throw new IonaClientError(
          undefined,
          `Request timed out after ${this.timeoutMs}ms`,
          error,
        );
      }
      throw new IonaClientError(
        undefined,
        `Network error: ${error instanceof Error ? error.message : String(error)}`,
        error,
      );
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Build common request headers.
   */
  private buildHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Accept': 'application/json',
    };
    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }
    return headers;
  }

  /**
   * Parse an error response and throw a structured IonaClientError.
   */
  private async handleErrorResponse(response: Response): Promise<never> {
    let body: IonaErrorBody | undefined;
    try {
      body = (await response.json()) as IonaErrorBody;
    } catch {
      // ignore parse errors
    }

    const message = body?.error?.message ?? `Request failed: ${response.status} ${response.statusText}`;
    this.logger('error', message, { status: response.status, body });
    throw new IonaClientError(response.status, message);
  }

  /**
   * Promise‑based delay.
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
