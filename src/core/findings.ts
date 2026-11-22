import { fingerprint } from "./fingerprint.js";
import type { CheckMeta, Evidence, SchemaFinding, Severity } from "./types.js";

export const TOOL_NAME = "stackaudit";

export interface InternalFinding {
  checkId: string;
  title: string;
  severity: Severity;
  isReview: boolean;
  status: "confirmed" | "unconfirmed" | "fixed";
  detail: string;
  affected: string[];
  references: string[];
  remediation: string;
  cwe?: string;
  owasp?: string;
  fingerprint: string;
}

const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export function severityRank(severity: Severity): number {
  return SEVERITY_ORDER.indexOf(severity);
}

export function toInternal(
  meta: CheckMeta,
  evidence: Evidence,
  baseUrl: string,
): InternalFinding {
  const isReview = evidence.severity === "review";
  const severity: Severity = isReview
    ? "info"
    : (evidence.severity as Severity);
  const title = isReview ? `Review: ${evidence.title}` : evidence.title;
  return {
    checkId: meta.id,
    title,
    severity,
    isReview,
    status: evidence.status ?? "unconfirmed",
    detail: evidence.detail,
    affected: evidence.affected ?? [],
    references: dedupe([meta.reference, ...(evidence.references ?? [])]),
    remediation: meta.remediation,
    cwe: evidence.cwe,
    owasp: evidence.owasp,
    fingerprint: fingerprint([baseUrl, meta.id, evidence.dedupeKey]),
  };
}

export function toSchemaFinding(
  finding: InternalFinding,
  index: number,
  version: string | null,
): SchemaFinding {
  const id = `SA-${String(index + 1).padStart(2, "0")}`;
  const out: SchemaFinding = {
    schemaVersion: 1,
    id,
    title: finding.title,
    status: finding.status,
    severity: finding.severity,
    tool: { name: TOOL_NAME, version },
    fingerprint: finding.fingerprint,
  };
  if (finding.affected.length) out.affected = finding.affected;
  if (finding.references.length) out.references = finding.references;
  if (finding.cwe) out.cwe = finding.cwe;
  if (finding.owasp) out.owasp = finding.owasp;
  return out;
}

function dedupe(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}
