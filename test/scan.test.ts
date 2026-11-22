import { describe, expect, it } from "vitest";
import { scan } from "../src/scanner.js";
import { toSchemaFindings } from "../src/format/json.js";
import { validateFindings } from "../src/core/schema.js";
import {
  BASE,
  FAKE_SERVICE_JWT,
  cleanClient,
  vulnerableClient,
} from "./fixtures.js";

async function passiveScan() {
  const client = vulnerableClient();
  const result = await scan({
    url: BASE,
    mode: "passive",
    authorized: false,
    client,
    version: "0.1.0",
  });
  return { client, result };
}

async function activeScan() {
  const client = vulnerableClient();
  const result = await scan({
    url: BASE,
    mode: "active",
    authorized: true,
    client,
    version: "0.1.0",
  });
  return { client, result };
}

describe("passive scan on the vulnerable fixture", () => {
  it("detects platforms", async () => {
    const { result } = await passiveScan();
    expect(result.platforms).toContain("vercel");
    expect(result.platforms).toContain("supabase");
  });

  it("flags the service_role key in the bundle as critical/confirmed", async () => {
    const { result } = await passiveScan();
    const secret = result.findings.find(
      (f) => f.checkId === "supabase-key-in-bundle" && f.severity === "critical",
    );
    expect(secret?.status).toBe("confirmed");
  });

  it("flags exposed .env and .git", async () => {
    const { result } = await passiveScan();
    const ids = result.findings
      .filter((f) => f.checkId === "exposed-dotfiles")
      .flatMap((f) => f.affected);
    expect(ids.some((a) => a.endsWith("/.env"))).toBe(true);
    expect(ids.some((a) => a.includes(".git"))).toBe(true);
  });

  it("flags the public source map", async () => {
    const { result } = await passiveScan();
    expect(
      result.findings.some((f) => f.checkId === "public-source-map"),
    ).toBe(true);
  });

  it("does not run active checks in passive mode", async () => {
    const { result } = await passiveScan();
    expect(
      result.findings.some((f) => f.checkId === "supabase-table-count"),
    ).toBe(false);
  });

  it("never sends the service secret to any host", async () => {
    const { client } = await passiveScan();
    for (const entry of client.log) {
      expect(entry.url).not.toContain(FAKE_SERVICE_JWT);
      expect(JSON.stringify(entry.headers)).not.toContain(FAKE_SERVICE_JWT);
    }
  });

  it("emits findings that validate against finding.schema.json", async () => {
    const { result } = await passiveScan();
    const schemaFindings = toSchemaFindings(result, "0.1.0");
    const validation = validateFindings(schemaFindings);
    expect(validation.errors).toEqual([]);
    expect(validation.valid).toBe(true);
  });
});

describe("active scan", () => {
  it("counts rows via HEAD + count and classifies sensitivity", async () => {
    const { result } = await activeScan();
    const users = result.findings.find(
      (f) => f.checkId === "supabase-table-count" && f.title.includes("users"),
    );
    expect(users?.severity).toBe("high");
    expect(users?.detail).toContain("1452");
  });

  it("maps a non-sensitive table to the REVIEW concept (info severity)", async () => {
    const { result } = await activeScan();
    const products = result.findings.find((f) =>
      f.title.toLowerCase().includes("products"),
    );
    expect(products?.isReview).toBe(true);
    expect(products?.severity).toBe("info");
  });

  it("only ever uses HEAD against /rest/v1 (never downloads rows)", async () => {
    const { client } = await activeScan();
    const restCalls = client.log.filter((e) => e.url.includes("/rest/v1/"));
    expect(restCalls.length).toBeGreaterThan(0);
    for (const call of restCalls) {
      expect(call.method).toBe("HEAD");
    }
  });

  it("flags the listable storage bucket via POST", async () => {
    const { result, client } = await activeScan();
    expect(
      result.findings.some((f) => f.checkId === "supabase-storage-listable"),
    ).toBe(true);
    const listCalls = client.log.filter((e) =>
      e.url.includes("/storage/v1/object/list/"),
    );
    expect(listCalls.every((c) => c.method === "POST")).toBe(true);
  });

  it("active findings also validate against the schema", async () => {
    const { result } = await activeScan();
    const validation = validateFindings(toSchemaFindings(result, "0.1.0"));
    expect(validation.errors).toEqual([]);
  });
});

describe("clean fixture", () => {
  it("produces no high/critical findings", async () => {
    const client = cleanClient();
    const result = await scan({
      url: BASE,
      mode: "passive",
      authorized: false,
      client,
      version: "0.1.0",
    });
    const serious = result.findings.filter(
      (f) => f.severity === "critical" || f.severity === "high",
    );
    expect(serious).toEqual([]);
  });
});
