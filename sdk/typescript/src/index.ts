/**
 * IONA RPC Client
 *
 * Provides a strongly‑typed client for the IONA node's HTTP endpoints.
 */

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

export type HealthResponse = string;

export interface ClientOptions {
  /** Request timeout in milliseconds (default: 5000) */
  timeoutMs?: number;
  /** Additional fetch options */
  fetchOptions?: RequestInit;
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

  constructor(baseUrl: string, options: ClientOptions = {}) {
    // Normalise base URL (remove trailing slash if present)
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.timeoutMs = options.timeoutMs ?? 5000;
    this.fetchOptions = options.fetchOptions ?? {};
  }

  /**
   * Perform a fetch request with a timeout.
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
   * GET /health
   * Returns the health status of the node (plain text).
   */
  async health(): Promise<HealthResponse> {
    const url = `${this.baseUrl}/health`;
    try {
      const response = await this.fetchWithTimeout(url, { method: 'GET' });
      if (!response.ok) {
        throw new IonaClientError(
          response.status,
          `Health check failed: ${response.status} ${response.statusText}`,
        );
      }
      return await response.text();
    } catch (error) {
      if (error instanceof IonaClientError) throw error;
      throw new IonaClientError(undefined, 'Health check failed', error);
    }
  }
}
