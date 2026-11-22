import type { InternalFinding } from "../core/findings.js";
import type { ScanResult } from "../scanner.js";
import type { Severity } from "../core/types.js";

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

const ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const WORD: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

export function renderHtml(result: ScanResult, version: string | null): string {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of result.findings) counts[f.severity] += 1;

  const summary = ORDER.map(
    (s) =>
      `<div class="stat-tile sev-${s}"><span class="stat">${counts[s]}</span><span class="label">${WORD[s]}</span></div>`,
  ).join("");

  const findingCards = result.findings
    .map((f) => findingCard(f))
    .join("\n");

  const platforms =
    result.platforms.filter((p) => p !== "unknown").join(", ") || "none";

  return `<!doctype html>
<html lang="en" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>stackaudit report — ${esc(result.baseUrl)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root, [data-theme="light"] {
  --bg:#f6f6f3; --surface:#ffffff; --ink:#111318; --ink-soft:#3b3f4a;
  --muted:#6b707c; --line:#e3e4e8; --brand:#0057ff; --accent:#0057ff;
  --brand-soft:#e8efff; --code-bg:#111318; --code-fg:#e9ecf5;
  --sev-critical:#b5283b; --sev-high:#cc5a1e; --sev-medium:#c79a12;
  --sev-low:#3b7a46; --sev-info:#8a93a1;
  --radius-md:16px; --radius-lg:18px; --radius-pill:999px;
  --font-display:"Space Grotesk",ui-sans-serif,system-ui,sans-serif;
  --font-mono:"IBM Plex Mono",ui-monospace,Menlo,Consolas,monospace;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg:#111318; --surface:#1a1d24; --ink:#e9ecf5; --ink-soft:#b8b9ba;
    --muted:#8a90a2; --line:#292b2f; --accent:#8fb2ff; --brand-soft:#0d2452;
    --sev-critical:#ff7a85; --sev-high:#f5b26b; --sev-medium:#e0b43a;
    --sev-low:#5ee6a0; --sev-info:#8a93a1;
  }
}
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--ink);
  font-family:var(--font-display); line-height:1.55; }
.wrap { max-width:1120px; margin:0 auto; padding:48px 16px 88px; }
.brand { font-family:var(--font-display); font-weight:600; font-size:28px;
  letter-spacing:-0.03em; }
.brand .slash { color:var(--brand); }
.eyebrow { font-family:var(--font-mono); font-size:12px; letter-spacing:0.12em;
  text-transform:uppercase; color:var(--muted); }
h1 { font-family:var(--font-display); font-size:40px; letter-spacing:-0.035em;
  margin:12px 0 4px; }
.meta { font-family:var(--font-mono); font-size:13px; color:var(--muted);
  margin-bottom:32px; }
.summary { display:flex; flex-wrap:wrap; gap:12px; margin-bottom:48px; }
.stat-tile { background:var(--surface); border:1px solid var(--line);
  border-radius:var(--radius-lg); padding:16px 20px; min-width:110px;
  display:flex; flex-direction:column; gap:4px; }
.stat { font-family:var(--font-mono); font-size:26px; font-variant-numeric:tabular-nums; }
.label { font-family:var(--font-mono); font-size:10.5px; letter-spacing:0.12em;
  color:var(--muted); }
.stat-tile.sev-critical .stat { color:var(--sev-critical); }
.stat-tile.sev-high .stat { color:var(--sev-high); }
.stat-tile.sev-medium .stat { color:var(--sev-medium); }
.stat-tile.sev-low .stat { color:var(--sev-low); }
.stat-tile.sev-info .stat { color:var(--sev-info); }
.finding { background:var(--surface); border:1px solid var(--line);
  border-left-width:4px; border-radius:var(--radius-md); padding:20px 24px;
  margin-bottom:16px; }
.finding.sev-critical { border-left-color:var(--sev-critical); }
.finding.sev-high { border-left-color:var(--sev-high); }
.finding.sev-medium { border-left-color:var(--sev-medium); }
.finding.sev-low { border-left-color:var(--sev-low); }
.finding.sev-info { border-left-color:var(--sev-info); }
.badge { font-family:var(--font-mono); font-size:11px; letter-spacing:0.06em;
  border-radius:var(--radius-pill); padding:2px 10px; border:1px solid var(--line);
  color:var(--ink); }
.finding h3 { font-family:var(--font-display); font-size:18px; margin:10px 0 8px;
  letter-spacing:-0.01em; }
.finding p { margin:6px 0; color:var(--ink-soft); font-size:15px; }
.kv { font-family:var(--font-mono); font-size:12.5px; color:var(--muted);
  word-break:break-all; }
.remediation { background:var(--brand-soft); border-radius:12px; padding:10px 14px;
  font-size:14px; color:var(--ink); margin-top:10px; }
footer { margin-top:48px; font-family:var(--font-mono); font-size:12px;
  color:var(--muted); border-top:1px solid var(--line); padding-top:16px; }
</style>
</head>
<body>
<main class="wrap">
  <div class="brand"><span class="slash">../</span> stackaudit</div>
  <div class="eyebrow">MISCONFIGURATION REPORT</div>
  <h1>${esc(result.baseUrl)}</h1>
  <div class="meta">mode: ${esc(result.mode)} · platforms: ${esc(platforms)} · requests: ${result.requestCount} · version: ${esc(version ?? "dev")}</div>
  <section class="summary">${summary}</section>
  <section>${findingCards || "<p>No findings.</p>"}</section>
  <footer>Generated by stackaudit. Findings default to status "unconfirmed"; verify before reporting. Secrets are reported, never validated against their provider.</footer>
</main>
</body>
</html>`;
}

function findingCard(f: InternalFinding): string {
  const word = f.isReview ? "REVIEW" : WORD[f.severity];
  const affected = f.affected.length
    ? `<p class="kv">affected: ${esc(f.affected.join(", "))}</p>`
    : "";
  const remediation = f.remediation
    ? `<div class="remediation"><strong>Remediation:</strong> ${esc(f.remediation)}</div>`
    : "";
  const refs = f.references.length
    ? `<p class="kv">refs: ${f.references.map((r) => `<a href="${esc(r)}">${esc(r)}</a>`).join(" · ")}</p>`
    : "";
  return `<article class="finding sev-${f.severity}">
  <span class="badge">${esc(word)}</span>
  <h3>${esc(f.title)}</h3>
  <p>${esc(f.detail)}</p>
  ${affected}
  <p class="kv">status: ${esc(f.status)} · check: ${esc(f.checkId)}${f.cwe ? ` · ${esc(f.cwe)}` : ""}</p>
  ${refs}
  ${remediation}
</article>`;
}
