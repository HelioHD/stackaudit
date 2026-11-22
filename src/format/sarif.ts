import { TOOL_NAME } from "../core/findings.js";
import type { ScanResult } from "../scanner.js";
import type { Severity } from "../core/types.js";

const SEVERITY_TO_LEVEL: Record<Severity, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

const SEVERITY_TO_SCORE: Record<Severity, string> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.0",
  low: "3.0",
  info: "0.0",
};

export function renderSarif(result: ScanResult, version: string | null): string {
  const ruleMap = new Map<string, { id: string; name: string; help: string }>();
  for (const f of result.findings) {
    if (!ruleMap.has(f.checkId)) {
      ruleMap.set(f.checkId, {
        id: f.checkId,
        name: f.title,
        help: f.remediation || "See stackaudit documentation.",
      });
    }
  }

  const rules = [...ruleMap.values()].map((r) => ({
    id: r.id,
    name: r.name,
    shortDescription: { text: r.name },
    helpUri: "https://github.com/HelioHD/stackaudit",
    help: { text: r.help },
  }));

  const results = result.findings.map((f) => ({
    ruleId: f.checkId,
    level: SEVERITY_TO_LEVEL[f.severity],
    message: { text: `${f.title}. ${f.detail}` },
    partialFingerprints: { stackauditFingerprint: f.fingerprint },
    properties: {
      severity: f.severity,
      "security-severity": SEVERITY_TO_SCORE[f.severity],
      status: f.status,
      review: f.isReview,
    },
    locations: f.affected.length
      ? f.affected.map((a) => ({
          physicalLocation: {
            artifactLocation: { uri: a },
          },
        }))
      : [
          {
            physicalLocation: {
              artifactLocation: { uri: result.baseUrl },
            },
          },
        ],
  }));

  const sarif = {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            version: version ?? "0.0.0",
            informationUri: "https://github.com/HelioHD/stackaudit",
            rules,
          },
        },
        results,
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}
