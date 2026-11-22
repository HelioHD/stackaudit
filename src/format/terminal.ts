import type { InternalFinding } from "../core/findings.js";
import type { ScanResult } from "../scanner.js";
import type { Severity } from "../core/types.js";

const TRUECOLOR: Record<Severity | "accent", [number, number, number]> = {
  accent: [143, 178, 255],
  critical: [255, 122, 133],
  high: [245, 178, 107],
  medium: [224, 180, 58],
  low: [94, 230, 160],
  info: [138, 147, 161],
};

const ANSI_BASIC: Record<Severity | "accent", number> = {
  accent: 12,
  critical: 9,
  high: 11,
  medium: 3,
  low: 10,
  info: 8,
};

const SEVERITY_WORD: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

interface ColorOptions {
  noColor: boolean;
  truecolor: boolean;
}

function colorize(
  text: string,
  key: Severity | "accent",
  opts: ColorOptions,
): string {
  if (opts.noColor) return text;
  if (opts.truecolor) {
    const [r, g, b] = TRUECOLOR[key];
    return `\u001b[38;2;${r};${g};${b}m${text}\u001b[0m`;
  }
  return `\u001b[38;5;${ANSI_BASIC[key]}m${text}\u001b[0m`;
}

function label(f: InternalFinding, opts: ColorOptions): string {
  const word = f.isReview ? "REVIEW" : SEVERITY_WORD[f.severity];
  return colorize(`[${word}]`, f.severity, opts);
}

export function renderTerminal(
  result: ScanResult,
  env: NodeJS.ProcessEnv = process.env,
): string {
  const opts: ColorOptions = {
    noColor: env.NO_COLOR !== undefined,
    truecolor:
      env.COLORTERM === "truecolor" || env.COLORTERM === "24bit",
  };
  const lines: string[] = [];
  const header = colorize("../ stackaudit", "accent", opts);
  lines.push(`${header}  ${result.baseUrl}`);
  lines.push(
    `mode: ${result.mode}   platforms: ${
      result.platforms.filter((p) => p !== "unknown").join(", ") || "none"
    }   requests: ${result.requestCount}`,
  );
  lines.push("");

  const counts = countBySeverity(result.findings);
  const summary = (["critical", "high", "medium", "low", "info"] as Severity[])
    .map((s) => colorize(`${SEVERITY_WORD[s]} ${counts[s]}`, s, opts))
    .join("  ");
  lines.push(summary);
  lines.push("");

  if (result.findings.length === 0) {
    lines.push("No findings.");
    return lines.join("\n");
  }

  for (const f of result.findings) {
    lines.push(`${label(f, opts)} ${f.title}`);
    lines.push(`    ${f.detail}`);
    if (f.affected.length) lines.push(`    affected: ${f.affected.join(", ")}`);
    lines.push(`    status: ${f.status}   check: ${f.checkId}`);
    lines.push("");
  }
  return lines.join("\n").trimEnd();
}

function countBySeverity(
  findings: InternalFinding[],
): Record<Severity, number> {
  const out: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of findings) out[f.severity] += 1;
  return out;
}
