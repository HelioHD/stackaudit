import { collectArtifacts } from "../core/collect.js";
import type { Evidence, ScanContext } from "../core/types.js";

const SUPABASE_URL_RE = /https:\/\/[a-z0-9]{20}\.supabase\.co/i;

export async function detectPlatforms(ctx: ScanContext): Promise<Evidence[]> {
  const { html, bundles } = await collectArtifacts(ctx);
  const root = await ctx.get("/");
  const headers = root.headers;
  const evidence: Evidence[] = [];
  const haystack = [html, ...bundles.map((b) => b.content)].join("\n");

  const server = (headers["server"] ?? "").toLowerCase();
  const poweredBy = (headers["x-powered-by"] ?? "").toLowerCase();

  if (
    headers["x-vercel-id"] !== undefined ||
    server.includes("vercel") ||
    /\.vercel\.app/i.test(ctx.baseUrl)
  ) {
    ctx.platforms.add("vercel");
  }
  if (
    server.includes("render") ||
    headers["x-render-origin-server"] !== undefined ||
    /\.onrender\.com/i.test(ctx.baseUrl) ||
    poweredBy.includes("render")
  ) {
    ctx.platforms.add("render");
  }

  const match = haystack.match(SUPABASE_URL_RE);
  if (match) {
    ctx.platforms.add("supabase");
    ctx.supabaseUrl = match[0].replace(/\/+$/, "");
  }

  if (ctx.platforms.size === 0) {
    ctx.platforms.add("unknown");
  }

  const detected = [...ctx.platforms].filter((p) => p !== "unknown");
  if (detected.length) {
    evidence.push({
      title: `Platforms detected: ${detected.join(", ")}`,
      severity: "info",
      status: "confirmed",
      detail: `stackaudit identified ${detected.join(
        ", ",
      )} from headers, host or bundle. Supabase project: ${
        ctx.supabaseUrl ?? "n/a"
      }.`,
      dedupeKey: `platforms:${detected.sort().join(",")}`,
    });
  }
  return evidence;
}
