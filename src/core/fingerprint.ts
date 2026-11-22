import { createHash } from "node:crypto";

export function fingerprint(parts: string[]): string {
  const hash = createHash("sha256");
  hash.update(parts.join("\u0000"));
  return `sha256:${hash.digest("hex")}`;
}
