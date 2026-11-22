import { detectPlatforms } from "./checks/detect.js";
import { checks } from "./checks/registry.js";
import {
  type InternalFinding,
  severityRank,
  toInternal,
} from "./core/findings.js";
import { ScanContext, type Check, type HttpClient, type Mode } from "./core/types.js";

export interface ScanOptions {
  url: string;
  mode: Mode;
  authorized: boolean;
  client: HttpClient;
  version: string | null;
}

export interface ScanResult {
  baseUrl: string;
  mode: Mode;
  platforms: string[];
  findings: InternalFinding[];
  requestCount: number;
}

function modeAllows(checkMode: Mode, ctx: ScanContext): boolean {
  if (checkMode === "passive") return true;
  if (checkMode === "active") return ctx.mode === "active" && ctx.authorized;
  return false;
}

export async function scan(options: ScanOptions): Promise<ScanResult> {
  const ctx = new ScanContext({
    baseUrl: options.url,
    mode: options.mode,
    authorized: options.authorized,
    client: options.client,
    version: options.version,
  });

  const findings: InternalFinding[] = [];
  const detected = await detectPlatforms(ctx);
  for (const ev of detected) {
    findings.push(
      toInternal(
        {
          id: "platform-detect",
          title: "Platform detection",
          platform: "unknown",
          modeRequired: "passive",
          defaultSeverity: "info",
          reference: "",
          remediation: "",
        },
        ev,
        ctx.baseUrl,
      ),
    );
  }

  for (const check of checks) {
    if (!modeAllows(check.meta.modeRequired, ctx)) continue;
    try {
      const evidence = await Promise.resolve(check.run(ctx));
      for (const ev of evidence) {
        findings.push(toInternal(check.meta, ev, ctx.baseUrl));
      }
    } catch (err) {
      findings.push(
        toInternal(
          check.meta,
          {
            title: `Check ${check.meta.id} failed to run`,
            severity: "info",
            status: "unconfirmed",
            detail: `The check raised: ${String(err)}`,
            dedupeKey: `error:${check.meta.id}`,
          },
          ctx.baseUrl,
        ),
      );
    }
  }

  findings.sort((a, b) => severityRank(a.severity) - severityRank(b.severity));

  return {
    baseUrl: ctx.baseUrl,
    mode: ctx.mode,
    platforms: [...ctx.platforms],
    findings,
    requestCount: ctx.client.log.length,
  };
}

export { checks };
export type { Check };
