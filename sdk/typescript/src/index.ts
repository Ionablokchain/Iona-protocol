export type HealthResponse = string;

export class IonaClient {
  constructor(public baseUrl: string) {}

  async health(): Promise<HealthResponse> {
    const r = await fetch(`${this.baseUrl}/health`);
    if (!r.ok) throw new Error(`health failed: ${r.status}`);
    return await r.text();
  }
}
