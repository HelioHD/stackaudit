import { describe, expect, it } from "vitest";
import { scan } from "../src/scanner.js";
import { renderSarif } from "../src/format/sarif.js";
import { renderHtml } from "../src/format/html.js";
import { renderTerminal } from "../src/format/terminal.js";
import { fingerprint } from "../src/core/fingerprint.js";
import { BASE, vulnerableClient } from "./fixtures.js";

async function result() {
  return scan({
    url: BASE,
    mode: "active",
    authorized: true,
    client: vulnerableClient(),
    version: "0.1.0",
  });
}

describe("fingerprint", () => {
  it("is a stable sha256 hex string", () => {
    const a = fingerprint(["x", "y"]);
    const b = fingerprint(["x", "y"]);
    expect(a).toBe(b);
    expect(a).toMatch(/^sha256:[a-f0-9]{64}$/);
  });
});

describe("sarif output", () => {
  it("is well-formed SARIF 2.1.0 with rules and results", async () => {
    const sarif = JSON.parse(renderSarif(await result(), "0.1.0"));
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe("stackaudit");
    expect(Array.isArray(sarif.runs[0].tool.driver.rules)).toBe(true);
    expect(sarif.runs[0].results.length).toBeGreaterThan(0);
    for (const r of sarif.runs[0].results) {
      expect(["error", "warning", "note"]).toContain(r.level);
      expect(r.ruleId).toBeTruthy();
    }
  });
});

describe("html output", () => {
  it("renders a self-contained page with the Delfino wordmark", async () => {
    const html = renderHtml(await result(), "0.1.0");
    expect(html).toContain("<!doctype html>");
    expect(html).toContain("../");
    expect(html).toContain("Space Grotesk");
    expect(html).toContain(BASE);
  });
});

describe("terminal output", () => {
  it("always writes the severity word and respects NO_COLOR", async () => {
    const text = renderTerminal(await result(), { NO_COLOR: "1" });
    expect(text).toContain("CRITICAL");
    expect(text).not.toContain("\u001b[");
  });

  it("emits ANSI when color is allowed", async () => {
    const text = renderTerminal(await result(), { COLORTERM: "truecolor" });
    expect(text).toContain("\u001b[");
  });
});
