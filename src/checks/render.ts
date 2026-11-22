import type { Check, Evidence, ScanContext } from "../core/types.js";

interface ExposedPath {
  path: string;
  title: string;
  severity: Evidence["severity"];
  signature: (body: string) => boolean;
  cwe: string;
}

const EXPOSED_PATHS: ExposedPath[] = [
  {
    path: "/.env",
    title: "Environment file (.env) publicly readable",
    severity: "critical",
    signature: (b) => /^\s*[A-Z0-9_]+\s*=.+/m.test(b),
    cwe: "CWE-538",
  },
  {
    path: "/.git/config",
    title: "Exposed .git/config",
    severity: "high",
    signature: (b) => /\[core\]/.test(b) || /\[remote /.test(b),
    cwe: "CWE-538",
  },
  {
    path: "/.git/HEAD",
    title: "Exposed .git directory (HEAD reachable)",
    severity: "high",
    signature: (b) => /ref:\s*refs\//.test(b),
    cwe: "CWE-538",
  },
];

export const exposedFilesCheck: Check = {
  meta: {
    id: "exposed-dotfiles",
    title: "Sensitive dotfiles exposed on the API host",
    platform: "render",
    modeRequired: "passive",
    defaultSeverity: "high",
    reference:
      "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url",
    remediation:
      "Block access to dotfiles at the server/proxy; never deploy .env or .git to the served root.",
  },
  async run(ctx: ScanContext): Promise<Evidence[]> {
    const out: Evidence[] = [];
    for (const target of EXPOSED_PATHS) {
      const res = await ctx.get(target.path);
      if (res.status === 200 && target.signature(res.body)) {
        out.push({
          title: target.title,
          severity: target.severity,
          status: "confirmed",
          detail: `${ctx.baseUrl}${target.path} returned HTTP 200 with content matching a ${target.path} signature.`,
          affected: [`${ctx.baseUrl}${target.path}`],
          cwe: target.cwe,
          owasp: "A05:2021",
          dedupeKey: `exposed:${target.path}`,
        });
      }
    }
    return out;
  },
};

export const stackTraceCheck: Check = {
  meta: {
    id: "stack-trace",
    title: "Stack trace leaked in response",
    platform: "render",
    modeRequired: "passive",
    defaultSeverity: "medium",
    reference: "https://cwe.mitre.org/data/definitions/209.html",
    remediation:
      "Disable verbose error output in production; return generic error pages.",
  },
  async run(ctx: ScanContext): Promise<Evidence[]> {
    const probes = ["/", "/__stackaudit_probe_404"];
    const out: Evidence[] = [];
    const signatures = [
      /at Object\.<anonymous>/,
      /\n\s+at .+\(.+:\d+:\d+\)/,
      /Traceback \(most recent call last\)/,
      /Exception in thread/,
    ];
    for (const path of probes) {
      const res = await ctx.get(path);
      if (!res.body) continue;
      if (signatures.some((s) => s.test(res.body))) {
        out.push({
          title: `Stack trace exposed at ${path}`,
          severity: "medium",
          status: "confirmed",
          detail: `${ctx.baseUrl}${path} (HTTP ${res.status}) returned a response containing a server stack trace.`,
          affected: [`${ctx.baseUrl}${path}`],
          cwe: "CWE-209",
          owasp: "A05:2021",
          dedupeKey: `stacktrace:${path}`,
        });
        break;
      }
    }
    return out;
  },
};

export const corsCheck: Check = {
  meta: {
    id: "reflected-cors-credentials",
    title: "CORS reflects arbitrary origin with credentials",
    platform: "render",
    modeRequired: "passive",
    defaultSeverity: "high",
    reference:
      "https://portswigger.net/web-security/cors",
    remediation:
      "Do not reflect the Origin header; use an allowlist and never combine a wildcard/reflected origin with Access-Control-Allow-Credentials: true.",
  },
  async run(ctx: ScanContext): Promise<Evidence[]> {
    const probeOrigin = "https://stackaudit-probe.example";
    const res = await ctx.client.request("GET", `${ctx.baseUrl}/`, {
      origin: probeOrigin,
    });
    const acao = res.headers["access-control-allow-origin"];
    const acac = res.headers["access-control-allow-credentials"];
    if (acao === probeOrigin && acac === "true") {
      return [
        {
          title: "CORS reflects arbitrary Origin with credentials enabled",
          severity: "high",
          status: "confirmed",
          detail: `The server echoed Access-Control-Allow-Origin: ${probeOrigin} together with Access-Control-Allow-Credentials: true. Any site can read authenticated responses.`,
          affected: [`${ctx.baseUrl}/`],
          cwe: "CWE-942",
          owasp: "A05:2021",
          dedupeKey: "cors:reflected-credentials",
        },
      ];
    }
    return [];
  },
};

export const renderOriginBypassCheck: Check = {
  meta: {
    id: "render-origin-bypass",
    title: "Render origin reachable directly, bypassing the custom domain",
    platform: "render",
    modeRequired: "passive",
    defaultSeverity: "low",
    reference: "https://render.com/docs/custom-domains",
    remediation:
      "If the API must only be reached through a WAF/custom domain, restrict or firewall the *.onrender.com origin.",
  },
  async run(ctx: ScanContext): Promise<Evidence[]> {
    const html = ctx.artifacts?.html ?? "";
    const bundles = ctx.artifacts?.bundles ?? [];
    const haystack = [html, ...bundles.map((b) => b.content)].join("\n");
    const hosts = new Set<string>();
    for (const m of haystack.matchAll(/https?:\/\/([a-z0-9-]+\.onrender\.com)/gi)) {
      hosts.add(m[1]!.toLowerCase());
    }
    const baseHost = safeHost(ctx.baseUrl);
    const out: Evidence[] = [];
    for (const host of hosts) {
      if (host === baseHost) continue;
      const res = await ctx.get(`https://${host}/`);
      if (res.status > 0 && res.status < 500) {
        out.push({
          title: `Render origin ${host} is reachable directly`,
          severity: "low",
          status: "confirmed",
          detail: `${host} returned HTTP ${res.status}. If production traffic is meant to go through a protected custom domain, this origin bypasses it.`,
          affected: [`https://${host}/`],
          cwe: "CWE-441",
          dedupeKey: `render-bypass:${host}`,
        });
      }
    }
    return out;
  },
};

function safeHost(url: string): string {
  try {
    return new URL(url).host.toLowerCase();
  } catch {
    return "";
  }
}
