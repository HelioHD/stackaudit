import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import type { SchemaFinding } from "./types.js";

const here = dirname(fileURLToPath(import.meta.url));

function schemaPath(): string {
  return join(here, "..", "..", "schema", "finding.schema.json");
}

export function loadSchema(): object {
  return JSON.parse(readFileSync(schemaPath(), "utf8")) as object;
}

export function createValidator(): (finding: unknown) => {
  valid: boolean;
  errors: string[];
} {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  addFormats(ajv);
  const validate = ajv.compile(loadSchema());
  return (finding: unknown) => {
    const valid = validate(finding) as boolean;
    const errors = (validate.errors ?? []).map(
      (e) => `${e.instancePath || "/"} ${e.message ?? ""}`.trim(),
    );
    return { valid, errors };
  };
}

export function validateFindings(findings: SchemaFinding[]): {
  valid: boolean;
  errors: string[];
} {
  const check = createValidator();
  const errors: string[] = [];
  for (const f of findings) {
    const result = check(f);
    if (!result.valid) errors.push(`${f.id}: ${result.errors.join("; ")}`);
  }
  return { valid: errors.length === 0, errors };
}
