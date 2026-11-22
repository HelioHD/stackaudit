import { collectArtifacts } from "../core/collect.js";
import type { Check, Evidence, ScanContext } from "../core/types.js";

const SENSITIVE_NAME_RE =
  /user|client|customer|cliente|profile|perfil|email|cpf|phone|telefone|pessoa|account|conta|payment|pagamento|order|pedido/i;

function anonHeaders(key: string): Record<string, string> {
  return { apikey: key, authorization: `Bearer ${key}` };
}

function parseCount(contentRange: string | undefined): number | null {
  if (!contentRange) return null;
  const m = /\/(\d+)\s*$/.exec(contentRange);
  return m ? Number(m[1]) : null;
}

async function discoverNames(
  ctx: ScanContext,
  re: RegExp,
): Promise<string[]> {
  const { html, bundles } = await collectArtifacts(ctx);
  const haystack = [html, ...bundles.map((b) => b.content)].join("\n");
  const names = new Set<string>();
  for (const m of haystack.matchAll(re)) names.add(m[1]!);
  return [...names];
}

export const supabaseTableCountCheck: Check = {
  meta: {
    id: "supabase-table-count",
    title: "Supabase table readable via the public (anon) key",
    platform: "supabase",
    modeRequired: "active",
    defaultSeverity: "high",
    reference:
      "https://supabase.com/docs/guides/database/postgres/row-level-security",
    remediation:
      "Enable Row Level Security on the table and add policies that scope rows to the authenticated user.",
  },
  async run(ctx: ScanContext): Promise<Evidence[]> {
    if (!ctx.supabaseUrl || !ctx.supabaseAnonKey) return [];
    const tables = await discoverNames(
      ctx,
      /\.from\(\s*['"`]([a-zA-Z_][a-zA-Z0-9_]*)['"`]/g,
    );
    const out: Evidence[] = [];
    for (const table of tables) {
      const url = `${ctx.supabaseUrl}/rest/v1/${table}?select=*`;
      const res = await ctx.head(url, {
        ...anonHeaders(ctx.supabaseAnonKey),
        prefer: "count=exact",
        range: "0-0",
      });
      if (res.status === 401 || res.status === 403) continue;
      const count = parseCount(res.headers["content-range"]);
      if (count === null) continue;
      if (count === 0) {
        out.push({
          title: `Table "${table}" responds to the anon key (count=0)`,
          severity: "review",
          status: "unconfirmed",
          detail: `HEAD on ${table} with the public key returned count=0. An empty result does NOT prove RLS is off: RLS enabled with no matching policy also returns empty. Manual confirmation needed.`,
          affected: [url],
          dedupeKey: `table-empty:${table}`,
        });
        continue;
      }
      const sensitive = SENSITIVE_NAME_RE.test(table);
      out.push({
        title: sensitive
          ? `Sensitive table "${table}" exposes ${count} rows to the anon key`
          : `Table "${table}" exposes ${count} rows to the anon key`,
        severity: sensitive ? "high" : "review",
        status: "confirmed",
        detail: `HEAD + Prefer: count=exact on ${table} returned Content-Range total ${count} using only the public key. No rows were downloaded. ${
          sensitive
            ? "The table name suggests personal data."
            : "Name does not suggest personal data (e.g. a public product catalog may be intentional); classify manually."
        } INSERT/UPDATE permissiveness is NOT tested (never written).`,
        affected: [url],
        cwe: "CWE-284",
        owasp: "A01:2021",
        dedupeKey: `table:${table}`,
      });
    }
    return out;
  },
};

export const supabaseStorageCheck: Check = {
  meta: {
    id: "supabase-storage-listable",
    title: "Supabase storage bucket listable with the public key",
    platform: "supabase",
    modeRequired: "active",
    defaultSeverity: "medium",
    reference:
      "https://supabase.com/docs/guides/storage/security/access-control",
    remediation:
      "Add storage RLS policies; do not allow anonymous listing of private buckets.",
  },
  async run(ctx: ScanContext): Promise<Evidence[]> {
    if (!ctx.supabaseUrl || !ctx.supabaseAnonKey) return [];
    const buckets = await discoverNames(
      ctx,
      /\.storage\s*\.from\(\s*['"`]([a-zA-Z0-9_-]+)['"`]/g,
    );
    const out: Evidence[] = [];
    for (const bucket of buckets) {
      const url = `${ctx.supabaseUrl}/storage/v1/object/list/${bucket}`;
      const res = await ctx.client.request("POST", url, {
        ...anonHeaders(ctx.supabaseAnonKey),
        "content-type": "application/json",
      });
      if (res.status === 200 && res.body.trim().startsWith("[") &&
        res.body.trim() !== "[]") {
        out.push({
          title: `Storage bucket "${bucket}" is listable with the public key`,
          severity: "medium",
          status: "confirmed",
          detail: `POST ${url} (the Supabase list endpoint) returned object entries using only the public key. "Read-only" here includes this POST, which lists but never mutates.`,
          affected: [url],
          cwe: "CWE-284",
          owasp: "A01:2021",
          dedupeKey: `bucket:${bucket}`,
        });
      }
    }
    return out;
  },
};

export const supabaseAuthSettingsCheck: Check = {
  meta: {
    id: "supabase-auth-settings",
    title: "Supabase auth signup settings",
    platform: "supabase",
    modeRequired: "active",
    defaultSeverity: "info",
    reference: "https://supabase.com/docs/guides/auth",
    remediation:
      "Review open signup / autoconfirm; disable self-signup if the app is not meant to accept public registrations.",
  },
  async run(ctx: ScanContext): Promise<Evidence[]> {
    if (!ctx.supabaseUrl || !ctx.supabaseAnonKey) return [];
    const url = `${ctx.supabaseUrl}/auth/v1/settings`;
    const res = await ctx.client.request("GET", url, anonHeaders(ctx.supabaseAnonKey));
    if (res.status !== 200) return [];
    let data: Record<string, unknown>;
    try {
      data = JSON.parse(res.body) as Record<string, unknown>;
    } catch {
      return [];
    }
    const out: Evidence[] = [];
    if (data.disable_signup === false) {
      out.push({
        title: "Supabase public signup is enabled",
        severity: "review",
        status: "confirmed",
        detail: `GET /auth/v1/settings reports disable_signup=false. Open signup may be intended; confirm with the owner.`,
        affected: [url],
        dedupeKey: "auth:signup-open",
      });
    }
    if (data.mailer_autoconfirm === true) {
      out.push({
        title: "Supabase email autoconfirm is on",
        severity: "low",
        status: "confirmed",
        detail: `GET /auth/v1/settings reports mailer_autoconfirm=true; accounts are usable without verifying ownership of the email address.`,
        affected: [url],
        cwe: "CWE-287",
        dedupeKey: "auth:autoconfirm",
      });
    }
    return out;
  },
};

export const supabaseGraphqlCheck: Check = {
  meta: {
    id: "supabase-pg-graphql",
    title: "Supabase pg_graphql endpoint reachable",
    platform: "supabase",
    modeRequired: "active",
    defaultSeverity: "info",
    reference: "https://supabase.com/docs/guides/graphql",
    remediation:
      "If GraphQL is not used, disable pg_graphql; otherwise ensure RLS covers every type it can resolve.",
  },
  async run(ctx: ScanContext): Promise<Evidence[]> {
    if (!ctx.supabaseUrl || !ctx.supabaseAnonKey) return [];
    const url = `${ctx.supabaseUrl}/graphql/v1`;
    const res = await ctx.head(url, anonHeaders(ctx.supabaseAnonKey));
    if (res.status > 0 && res.status !== 404) {
      const rpcs = await discoverNames(
        ctx,
        /\.rpc\(\s*['"`]([a-zA-Z_][a-zA-Z0-9_]*)['"`]/g,
      );
      const rpcNote = rpcs.length
        ? ` Client calls these RPCs (verify none are SECURITY DEFINER with weak checks): ${rpcs.join(", ")}.`
        : "";
      return [
        {
          title: "pg_graphql endpoint is reachable",
          severity: "review",
          status: "confirmed",
          detail: `HEAD ${url} returned HTTP ${res.status}. The GraphQL surface is exposed; it is governed by the same RLS as REST.${rpcNote}`,
          affected: [url],
          dedupeKey: "supabase:graphql",
        },
      ];
    }
    return [];
  },
};
