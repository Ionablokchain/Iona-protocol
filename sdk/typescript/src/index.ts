/**
 * Iona TypeScript Client SDK
 *
 * This module provides a typed client for interacting with an Iona node's REST API.
 * It covers common endpoints like health checks, node status, transaction broadcasting,
 * ABCI queries, and more.
 *
 * ## Usage Example
 *
 * ```typescript
 * import { IonaClient } from 'iona-sdk';
 *
 * const client = new IonaClient({ baseUrl: 'http://localhost:26657' });
 *
 * async function demo() {
 *   const health = await client.health();
 *   console.log('Node health:', health);
 *
 *   const status = await client.getStatus();
 *   console.log('Node status:', status);
 *
 *   // Broadcast a transaction
 *   const txResult = await client.broadcastTxSync({
 *     tx: 'base64EncodedTxBytes'
 *   });
 *   console.log('Broadcast result:', txResult);
 * }
 * ```
 */

// ------------------------------
// Configuration
// ------------------------------

export interface ClientConfig {
  /** Base URL of the Iona node (e.g., http://localhost:26657) */
  baseUrl: string;
  /** Optional request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Optional headers to include in every request */
  headers?: Record<string, string>;
}

// ------------------------------
// Error Handling
// ------------------------------

export class IonaApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public statusText: string,
    public body?: any
  ) {
    super(message);
    this.name = 'IonaApiError';
  }
}

// ------------------------------
// Request Helper
// ------------------------------

async function request<T>(
  config: ClientConfig,
  path: string,
  options?: RequestInit
): Promise<T> {
  const url = `${config.baseUrl}${path}`;
  const controller = new AbortController();
  const timeoutId = setTimeout(
    () => controller.abort(),
    config.timeout ?? 30000
  );

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        ...config.headers,
        ...options?.headers,
      },
    });

    if (!response.ok) {
      let body;
      const contentType = response.headers.get('content-type');
      if (contentType?.includes('application/json')) {
        body = await response.json();
      } else {
        body = await response.text();
      }
      throw new IonaApiError(
        `Request failed: ${response.status} ${response.statusText}`,
        response.status,
        response.statusText,
        body
      );
    }

    // Handle empty responses
    const contentLength = response.headers.get('content-length');
    if (contentLength === '0' || response.status === 204) {
      return undefined as T;
    }

    const contentType = response.headers.get('content-type');
    if (contentType?.includes('application/json')) {
      return await response.json();
    } else {
      // Assume text
      return (await response.text()) as T;
    }
  } catch (error) {
    if (error instanceof IonaApiError) throw error;
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw new Error(`Request timeout after ${config.timeout ?? 30000}ms`);
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

// ------------------------------
// API Types (based on Iona OpenAPI spec)
// ------------------------------

export type HealthResponse = string;

export interface NodeStatus {
  node_info: {
    protocol_version: { p2p: string; block: string; app: string };
    id: string;
    listen_addr: string;
    network: string;
    version: string;
    channels: string;
    moniker: string;
    other: { tx_index: string; rpc_address: string };
  };
  sync_info: {
    latest_block_hash: string;
    latest_app_hash: string;
    latest_block_height: string;
    latest_block_time: string;
    catching_up: boolean;
  };
  validator_info: {
    address: string;
    pub_key: { type: string; value: string };
    voting_power: string;
  };
}

export interface BroadcastTxSyncResponse {
  code: number;
  data?: string;
  log: string;
  codespace?: string;
  hash: string;
}

export interface BroadcastTxCommitResponse {
  height: string;
  hash: string;
  deliver_tx?: {
    code: number;
    data?: string;
    log: string;
    codespace?: string;
  };
  check_tx: {
    code: number;
    data?: string;
    log: string;
    codespace?: string;
    gas_used?: string;
    gas_wanted?: string;
  };
}

export interface AbciQueryResponse {
  response: {
    code: number;
    log: string;
    info: string;
    index: string;
    key?: string;
    value?: string;
    proof?: string;
    height: string;
    codespace?: string;
  };
}

export interface TxRequest {
  /** Base64-encoded transaction bytes */
  tx: string;
}

// ------------------------------
// Main Client Class
// ------------------------------

export class IonaClient {
  private config: ClientConfig;

  constructor(config: ClientConfig) {
    this.config = config;
  }

  /**
   * Check node health (simple liveness probe)
   */
  async health(): Promise<HealthResponse> {
    return request<HealthResponse>(this.config, '/health');
  }

  /**
   * Get node status (sync info, validator info, etc.)
   */
  async getStatus(): Promise<NodeStatus> {
    return request<NodeStatus>(this.config, '/status');
  }

  /**
   * Broadcast a transaction asynchronously (returns immediately with check_tx result)
   */
  async broadcastTxSync(req: TxRequest): Promise<BroadcastTxSyncResponse> {
    return request<BroadcastTxSyncResponse>(this.config, '/broadcast_tx_sync', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  /**
   * Broadcast a transaction and wait for it to be committed (slower, but gives deliver_tx result)
   */
  async broadcastTxCommit(req: TxRequest): Promise<BroadcastTxCommitResponse> {
    return request<BroadcastTxCommitResponse>(this.config, '/broadcast_tx_commit', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  /**
   * Perform an ABCI query against the application state
   * @param path - Query path (e.g., "/store/balances/key")
   * @param data - Base64-encoded query data
   * @param height - Optional block height to query (0 for latest)
   */
  async abciQuery(path: string, data: string, height?: number): Promise<AbciQueryResponse> {
    const params = new URLSearchParams({
      path,
      data,
      ...(height !== undefined ? { height: height.toString() } : {}),
    });
    return request<AbciQueryResponse>(this.config, `/abci_query?${params}`);
  }

  /**
   * Get a specific block by height (or latest if height is undefined)
   */
  async getBlock(height?: number): Promise<any> {
    const path = height ? `/block?height=${height}` : '/block';
    return request<any>(this.config, path);
  }

  /**
   * Get transaction by hash
   */
  async getTx(hash: string): Promise<any> {
    return request<any>(this.config, `/tx?hash=0x${hash}`);
  }
}

// ------------------------------
// Re-export types for convenience
// ------------------------------

export * from './generated'; // Uncomment when OpenAPI generation is in place
