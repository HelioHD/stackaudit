import type { HttpClient, HttpRequestLog, HttpResponse } from "./types.js";

const DEFAULT_TIMEOUT_MS = 10_000;

export class FetchHttpClient implements HttpClient {
  readonly log: HttpRequestLog[] = [];
  private readonly userAgent: string;

  constructor(userAgent = "stackaudit") {
    this.userAgent = userAgent;
  }

  async request(
    method: string,
    url: string,
    headers: Record<string, string> = {},
  ): Promise<HttpResponse> {
    const merged = { "user-agent": this.userAgent, ...headers };
    this.log.push({ method, url, headers: merged });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);
    try {
      const res = await fetch(url, {
        method,
        headers: merged,
        redirect: "manual",
        signal: controller.signal,
      });
      const outHeaders: Record<string, string> = {};
      res.headers.forEach((value, key) => {
        outHeaders[key.toLowerCase()] = value;
      });
      const body = method === "HEAD" ? "" : await res.text();
      return { url, status: res.status, headers: outHeaders, body };
    } catch (err) {
      return {
        url,
        status: 0,
        headers: { "x-stackaudit-error": String(err) },
        body: "",
      };
    } finally {
      clearTimeout(timer);
    }
  }
}
