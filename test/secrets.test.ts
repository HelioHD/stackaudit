import { describe, expect, it } from "vitest";
import { inspectSupabaseKeys } from "../src/core/secrets.js";
import { scanWithGitleaks } from "../src/gitleaks/rules.js";
import {
  FAKE_ANON_JWT,
  FAKE_SB_SECRET,
  FAKE_SERVICE_JWT,
  FAKE_STRIPE,
  vulnerableBundle,
} from "./fixtures.js";

describe("supabase key inspection", () => {
  it("decodes the role claim of a legacy JWT instead of guessing", () => {
    const keys = inspectSupabaseKeys(
      `a=${FAKE_SERVICE_JWT};b=${FAKE_ANON_JWT}`,
    );
    const service = keys.find((k) => k.role === "service_role");
    const anon = keys.find((k) => k.role === "anon");
    expect(service?.isSecret).toBe(true);
    expect(service?.format).toBe("legacy-jwt");
    expect(anon?.isSecret).toBe(false);
  });

  it("detects the new sb_secret_ prefix", () => {
    const keys = inspectSupabaseKeys(`x=${FAKE_SB_SECRET}`);
    expect(keys[0]?.format).toBe("sb-secret");
    expect(keys[0]?.isSecret).toBe(true);
  });

  it("never returns the full secret in the redacted field", () => {
    const keys = inspectSupabaseKeys(`x=${FAKE_SB_SECRET}`);
    expect(keys[0]?.redacted).not.toContain("stackauditEXAMPLE");
  });
});

describe("gitleaks rule set", () => {
  it("flags a planted Stripe key", () => {
    const hits = scanWithGitleaks(vulnerableBundle());
    expect(hits.some((h) => h.match === FAKE_STRIPE)).toBe(true);
  });

  it("returns nothing on clean content", () => {
    expect(scanWithGitleaks("const x = 1;")).toHaveLength(0);
  });
});
