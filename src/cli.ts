#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { scan } from "./scanner.js";
import { FetchHttpClient } from "./core/http.js";
import { renderJson } from "./format/json.js";
import { renderSarif } from "./format/sarif.js";
import { renderHtml } from "./format/html.js";
import { renderTerminal } from "./format/terminal.js";
import type { Mode } from "./core/types.js";

interface Args {
  url?: string;
  mode: Mode;
  authorized: boolean;
  format: "terminal" | "json" | "sarif" | "html";
  out?: string;
  help: boolean;
  version: boolean;
}

function getVersion(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(
      readFileSync(join(here, "..", "package.json"), "utf8"),
    ) as { version?: string };
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

function parseArgs(argv: string[]): Args {
  const args: Args = {
    mode: "passive",
    authorized: false,
    format: "terminal",
    help: false,
    version: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i]!;
    if (a === "--help" || a === "-h") args.help = true;
    else if (a === "--version" || a === "-v") args.version = true;
    else if (a === "--authorized") args.authorized = true;
    else if (a === "--mode") args.mode = argv[++i] as Mode;
    else if (a === "--format") args.format = argv[++i] as Args["format"];
    else if (a === "--out" || a === "-o") args.out = argv[++i];
    else if (!a.startsWith("-")) args.url = a;
  }
  return args;
}

const HELP = `../ stackaudit — passive-first misconfig auditor for Supabase + Vercel + Render

Usage:
  npx stackaudit <url> [options]

Options:
  --mode <passive|active|config>  scan mode (default: passive)
  --authorized                    required to run active checks (HEAD + count only)
  --format <terminal|json|sarif|html>  output format (default: terminal)
  --out, -o <file>                write output to a file instead of stdout
  --version, -v                   print version
  --help, -h                      show this help

Legal posture:
  passive  only what a browser already receives (bundle, headers, .env, .git, source maps)
  active   needs --authorized; queries the Supabase public key with HEAD + Prefer: count=exact
           (reads the total from Content-Range; never downloads rows; never validates secrets)
  config   platform owner tokens — out of scope for this MVP (v2)
`;

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const version = getVersion();

  if (args.version) {
    process.stdout.write(`stackaudit ${version}\n`);
    return;
  }
  if (args.help || !args.url) {
    process.stdout.write(HELP);
    if (!args.url && !args.help) process.exitCode = 2;
    return;
  }

  if (args.mode === "config") {
    process.stderr.write(
      "config mode (platform owner tokens) is out of scope for this MVP; planned for v2.\n",
    );
    process.exitCode = 2;
    return;
  }

  if (args.mode === "active" && !args.authorized) {
    process.stderr.write(
      "active mode requires the explicit --authorized flag. Refusing to run active checks.\n",
    );
    process.exitCode = 2;
    return;
  }

  const client = new FetchHttpClient(`stackaudit/${version}`);
  const result = await scan({
    url: args.url,
    mode: args.mode,
    authorized: args.authorized,
    client,
    version,
  });

  let output: string;
  if (args.format === "json") output = renderJson(result, version);
  else if (args.format === "sarif") output = renderSarif(result, version);
  else if (args.format === "html") output = renderHtml(result, version);
  else output = renderTerminal(result);

  if (args.out) {
    writeFileSync(args.out, output);
    process.stdout.write(`Wrote ${args.format} report to ${args.out}\n`);
  } else {
    process.stdout.write(`${output}\n`);
  }
}

main().catch((err) => {
  process.stderr.write(`stackaudit failed: ${String(err)}\n`);
  process.exitCode = 1;
});
