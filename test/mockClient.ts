import type { HttpClient, HttpRequestLog, HttpResponse } from "../src/core/types.js";

export interface MockRoute {
  status: number;
  headers?: Record<string, string>;
  body?: string;
}

type RouteKey = string;

export class MockHttpClient implements HttpClient {
  readonly log: HttpRequestLog[] = [];
  private routes = new Map<RouteKey, MockRoute>();

  on(method: string, url: string, route: MockRoute): this {
    this.routes.set(`${method.toUpperCase()} ${url}`, route);
    return this;
  }

  async request(
    method: string,
    url: string,
    headers: Record<string, string> = {},
  ): Promise<HttpResponse> {
    this.log.push({ method, url, headers });
    const route =
      this.routes.get(`${method.toUpperCase()} ${url}`) ??
      this.routes.get(`GET ${url}`);
    if (!route) {
      return { url, status: 404, headers: {}, body: "" };
    }
    return {
      url,
      status: route.status,
      headers: route.headers ?? {},
      body: method === "HEAD" ? "" : route.body ?? "",
    };
  }
}
