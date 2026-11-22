import { collectArtifacts } from "../core/collect.js";
import { inspectSupabaseKeys } from "../core/secrets.js";
import type { Check, Evidence, ScanContext } from "../core/types.js";

export const supabaseKeyCheck: Check = {
  meta: {
    id: "supabase-key-in-bundle",
    title: "Supabase key exposed in client bundle",
    platform: "supabase",
    modeRequired: "passive",
    defaultSeverity: "critical",
    reference:
      "https://supabase.com/docs/guides/api/api-keys",
    remediation:
      "Never ship the service_role / sb_secret_ key to the browser. Keep it server-side only; rotate any key found in a bundle.",
  },
  async run(ctx: ScanContext): Promise<Evidence[]> {
    const { html, bundles } = await collectArtifacts(ctx);
    const sources = [
      { url: `${ctx.baseUrl}/`, content: html },
      ...bundles,
    ];
    const out: Evidence[] = [];
    for (const src of sources) {
      for (const key of inspectSupabaseKeys(src.content)) {
        if (!key.isSecret && !ctx.supabaseAnonKey) {
          ctx.supabaseAnonKey = key.raw;
        }
        if (key.isSecret) {
          out.push({
            title: `Supabase secret key (${key.format}, role=${
              key.role ?? "unknown"
            }) in client bundle`,
            severity: "critical",
            status: "confirmed",
            detail: `A secret-grade Supabase key (${key.redacted}) was found in ${src.url}. This key bypasses RLS and grants full database access.`,
            affected: [src.url],
            cwe: "CWE-312",
            owasp: "A05:2021",
            dedupeKey: `secret:${key.redacted}`,
          });
        } else {
          out.push({
            title: `Supabase ${key.format} (anon/publishable) key present in bundle`,
            severity: "info",
            status: "confirmed",
            detail: `A publishable/anon Supabase key (${key.redacted}) is present in ${src.url}. This is expected by design; it is only safe when Row Level Security is enforced on every table.`,
            affected: [src.url],
            dedupeKey: `anon:${key.redacted}`,
          });
        }
      }
    }
    return out;
  },
};
