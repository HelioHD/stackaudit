export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Mode = "passive" | "active" | "config";

export type Platform = "supabase" | "vercel" | "render" | "unknown";

export interface SchemaFinding {
  schemaVersion: 1;
  id: string;
  title: string;
  status: "confirmed" | "unconfirmed" | "fixed";
  severity: Severity;
  cwe?: string;
  owasp?: string;
  affected?: string[];
  references?: string[];
  tool: { name: string; version: string | null };
  fingerprint: string;
}

export interface HttpResponse {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
}

export interface HttpRequestLog {
  method: string;
  url: string;
  headers: Record<string, string>;
}

export interface HttpClient {
  request(
    method: string,
    url: string,
    headers?: Record<string, string>,
  ): Promise<HttpResponse>;
  readonly log: HttpRequestLog[];
}

export interface Resource {
  path: string;
  url: string;
  response: HttpResponse;
}

export interface Bundle {
  url: string;
  content: string;
}

export interface Evidence {
  title: string;
  severity: Severity | "review";
  status?: "confirmed" | "unconfirmed" | "fixed";
  detail: string;
  affected?: string[];
  references?: string[];
  cwe?: string;
  owasp?: string;
  dedupeKey: string;
}

export interface CheckMeta {
  id: string;
  title: string;
  platform: Platform;
  modeRequired: Mode;
  defaultSeverity: Severity | "review";
  reference: string;
  remediation: string;
}

export interface Check {
  meta: CheckMeta;
  run(ctx: ScanContext): Promise<Evidence[]> | Evidence[];
}

export interface ScanContextInit {
  baseUrl: string;
  mode: Mode;
  authorized: boolean;
  client: HttpClient;
  version: string | null;
}

export class ScanContext {
  readonly baseUrl: string;
  readonly mode: Mode;
  readonly authorized: boolean;
  readonly client: HttpClient;
  readonly version: string | null;
  platforms: Set<Platform> = new Set();
  supabaseUrl: string | null = null;
  supabaseAnonKey: string | null = null;
  artifacts: { html: string; bundles: Bundle[] } | null = null;
  private cache = new Map<string, HttpResponse>();

  constructor(init: ScanContextInit) {
    this.baseUrl = init.baseUrl.replace(/\/+$/, "");
    this.mode = init.mode;
    this.authorized = init.authorized;
    this.client = init.client;
    this.version = init.version;
  }

  resolve(path: string): string {
    if (/^https?:\/\//i.test(path)) return path;
    return `${this.baseUrl}/${path.replace(/^\/+/, "")}`;
  }

  async get(path: string): Promise<HttpResponse> {
    const url = this.resolve(path);
    const cached = this.cache.get(url);
    if (cached) return cached;
    const res = await this.client.request("GET", url);
    this.cache.set(url, res);
    return res;
  }

  async head(
    url: string,
    headers?: Record<string, string>,
  ): Promise<HttpResponse> {
    return this.client.request("HEAD", url, headers);
  }
}
