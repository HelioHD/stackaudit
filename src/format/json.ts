import { toSchemaFinding } from "../core/findings.js";
import type { ScanResult } from "../scanner.js";
import type { SchemaFinding } from "../core/types.js";

export function toSchemaFindings(
  result: ScanResult,
  version: string | null,
): SchemaFinding[] {
  return result.findings.map((f, i) => toSchemaFinding(f, i, version));
}

export function renderJson(result: ScanResult, version: string | null): string {
  return JSON.stringify(toSchemaFindings(result, version), null, 2);
}
