import { collectArtifacts } from "../core/collect.js";
import { redact } from "../core/secrets.js";
import { scanWithGitleaks } from "../gitleaks/rules.js";
import type { Check, Evidence, ScanContext } from "../core/types.js";

export const bundleSecretsCheck: Check = {
  meta: {
    id: "secret-in-bundle",
    title: "Secret detected in client bundle (gitleaks rules)",
    platform: "vercel",
    modeRequired: "passive",
    defaultSeverity: "high",
    reference: "https://github.com/gitleaks/gitleaks",
    remediation:
      "Move the credential to a server-side environment variable; never expose non-public secrets to client code. Rotate the leaked value.",
  },
  async run(ctx: ScanContext): Promise<Evidence[]> {
    const { html, bundles } = await collectArtifacts(ctx);
    const sources = [{ url: `${ctx.baseUrl}/`, content: html }, ...bundles];
    const out: Evidence[] = [];
    for (const src of sources) {
      for (const hit of scanWithGitleaks(src.content)) {
        const severity = hit.ruleId === "jwt" ? "medium" : "high";
        out.push({
          title: `${hit.description} exposed in ${shortName(src.url)}`,
          severity,
          status: "confirmed",
          detail: `gitleaks rule "${hit.ruleId}" matched ${redact(
            hit.match,
          )} in ${src.url}. The secret is reported, never validated against its provider.`,
          affected: [src.url],
          cwe: "CWE-312",
          owasp: "A05:2021",
          dedupeKey: `${hit.ruleId}:${hit.match}`,
        });
      }
    }
    return out;
  },
};

export const sourceMapCheck: Check = {
  meta: {
    id: "public-source-map",
    title: "Public source map exposes original source",
    platform: "vercel",
    modeRequired: "passive",
    defaultSeverity: "low",
    reference:
      "https://developer.mozilla.org/en-US/docs/Web/API/Document/currentScript",
    remediation:
      "Disable source map emission in production builds, or restrict access to .map files.",
  },
  async run(ctx: ScanContext): Promise<Evidence[]> {
    const { bundles } = await collectArtifacts(ctx);
    const out: Evidence[] = [];
    for (const bundle of bundles) {
      const m = /\/\/#\s*sourceMappingURL=(\S+)/.exec(bundle.content);
      if (!m) continue;
      const ref = m[1]!;
      if (ref.startsWith("data:")) continue;
      const mapUrl = ref.startsWith("http")
        ? ref
        : `${bundle.url.replace(/\/[^/]*$/, "")}/${ref}`;
      const res = await ctx.get(mapUrl);
      if (res.status === 200 && res.body.includes('"sources"')) {
        out.push({
          title: `Public source map at ${shortName(mapUrl)}`,
          severity: "low",
          status: "confirmed",
          detail: `${mapUrl} returned HTTP 200 with a sources array, exposing original (pre-minification) source.`,
          affected: [mapUrl],
          cwe: "CWE-540",
          dedupeKey: `sourcemap:${mapUrl}`,
        });
      }
    }
    return out;
  },
};

interface HeaderRule {
  header: string;
  title: string;
  severity: Evidence["severity"];
  cwe: string;
}

const HEADER_RULES: HeaderRule[] = [
  {
    header: "content-security-policy",
    title: "Missing Content-Security-Policy header",
    severity: "medium",
    cwe: "CWE-1021",
  },
  {
    header: "strict-transport-security",
    title: "Missing Strict-Transport-Security header",
    severity: "medium",
    cwe: "CWE-319",
  },
  {
    header: "referrer-policy",
    title: "Missing Referrer-Policy header",
    severity: "low",
    cwe: "CWE-200",
  },
];

export const securityHeadersCheck: Check = {
  meta: {
    id: "security-headers",
    title: "Security response headers",
    platform: "vercel",
    modeRequired: "passive",
    defaultSeverity: "medium",
    reference: "https://owasp.org/www-project-secure-headers/",
    remediation:
      "Add the missing headers at the edge (Vercel headers config) or in the framework response.",
  },
  async run(ctx: ScanContext): Promise<Evidence[]> {
    const root = await ctx.get("/");
    if (root.status === 0) return [];
    const headers = root.headers;
    const out: Evidence[] = [];
    for (const rule of HEADER_RULES) {
      if (headers[rule.header] === undefined) {
        out.push({
          title: rule.title,
          severity: rule.severity,
          status: "confirmed",
          detail: `The response for ${ctx.baseUrl}/ did not include the ${rule.header} header.`,
          affected: [`${ctx.baseUrl}/`],
          cwe: rule.cwe,
          owasp: "A05:2021",
          dedupeKey: `header:${rule.header}`,
        });
      }
    }
    const csp = headers["content-security-policy"] ?? "";
    const xfo = headers["x-frame-options"];
    if (!/frame-ancestors/i.test(csp) && xfo === undefined) {
      out.push({
        title: "Clickjacking protection missing (no frame-ancestors / X-Frame-Options)",
        severity: "medium",
        status: "confirmed",
        detail: `Neither a CSP frame-ancestors directive nor X-Frame-Options was present on ${ctx.baseUrl}/.`,
        affected: [`${ctx.baseUrl}/`],
        cwe: "CWE-1021",
        owasp: "A05:2021",
        dedupeKey: "header:frame-ancestors",
      });
    }
    return out;
  },
};

export const vercelOriginBypassCheck: Check = {
  meta: {
    id: "vercel-origin-bypass",
    title: "Vercel origin reachable directly, bypassing the custom domain",
    platform: "vercel",
    modeRequired: "passive",
    defaultSeverity: "low",
    reference:
      "https://vercel.com/docs/deployments/deployment-protection",
    remediation:
      "Enable Deployment Protection / disable public access to *.vercel.app if the app must only be reached through the WAF-protected custom domain.",
  },
  async run(ctx: ScanContext): Promise<Evidence[]> {
    const { html, bundles } = await collectArtifacts(ctx);
    const haystack = [html, ...bundles.map((b) => b.content)].join("\n");
    const hosts = new Set<string>();
    for (const m of haystack.matchAll(/https?:\/\/([a-z0-9-]+\.vercel\.app)/gi)) {
      hosts.add(m[1]!.toLowerCase());
    }
    const baseHost = safeHost(ctx.baseUrl);
    const out: Evidence[] = [];
    for (const host of hosts) {
      if (host === baseHost) continue;
      const res = await ctx.get(`https://${host}/`);
      if (res.status === 200) {
        out.push({
          title: `Vercel origin ${host} serves the app directly`,
          severity: "low",
          status: "confirmed",
          detail: `${host} returned HTTP 200. If the production entrypoint is a custom domain behind a WAF, this origin bypasses it.`,
          affected: [`https://${host}/`],
          cwe: "CWE-441",
          dedupeKey: `vercel-bypass:${host}`,
        });
      }
    }
    return out;
  },
};

function shortName(url: string): string {
  return url.split("/").pop() || url;
}

function safeHost(url: string): string {
  try {
    return new URL(url).host.toLowerCase();
  } catch {
    return "";
  }
}
