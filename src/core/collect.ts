import type { Bundle, ScanContext } from "./types.js";

const MAX_BUNDLES = 20;

export async function collectArtifacts(
  ctx: ScanContext,
): Promise<{ html: string; bundles: Bundle[] }> {
  if (ctx.artifacts) return ctx.artifacts;
  const root = await ctx.get("/");
  const html = root.body;
  const scriptUrls = extractScriptUrls(html, ctx.baseUrl);
  const bundles: Bundle[] = [];
  for (const url of scriptUrls.slice(0, MAX_BUNDLES)) {
    const res = await ctx.get(url);
    if (res.status === 200 && res.body) {
      bundles.push({ url, content: res.body });
    }
  }
  ctx.artifacts = { html, bundles };
  return ctx.artifacts;
}

export function extractScriptUrls(html: string, baseUrl: string): string[] {
  const urls = new Set<string>();
  const re = /<script[^>]+src=["']([^"']+)["']/gi;
  for (const m of html.matchAll(re)) {
    const src = m[1]!;
    urls.add(absolutize(src, baseUrl));
  }
  const modulePreload = /<link[^>]+rel=["']modulepreload["'][^>]+href=["']([^"']+)["']/gi;
  for (const m of html.matchAll(modulePreload)) {
    urls.add(absolutize(m[1]!, baseUrl));
  }
  return [...urls].filter((u) => /\.m?js(\?|$)/i.test(u));
}

function absolutize(src: string, baseUrl: string): string {
  if (/^https?:\/\//i.test(src)) return src;
  if (src.startsWith("//")) return `https:${src}`;
  return `${baseUrl}/${src.replace(/^\/+/, "")}`;
}
