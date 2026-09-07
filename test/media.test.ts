import { describe, expect, it } from "vitest";
import { acceptsMediaType, parseMediaType } from "../src/media";

describe("parseMediaType", () => {
  it("extracts the essence from a parameterized header", () => {
    expect(parseMediaType("application/dns-message")).toBe("application/dns-message");
    expect(parseMediaType("application/dns-message; charset=utf-8")).toBe("application/dns-message");
    expect(parseMediaType("  Application/DNS-Message ; charset=utf-8 ")).toBe("application/dns-message");
  });

  it("rejects structurally invalid input", () => {
    expect(parseMediaType("")).toBeNull();
    expect(parseMediaType("text")).toBeNull();
    expect(parseMediaType("; charset=utf-8")).toBeNull();
    expect(parseMediaType("/json")).toBeNull();
  });

  it("does NOT accept a prefix of the real type (no startsWith matching)", () => {
    expect(parseMediaType("application/dns-messageevil")).toBe("application/dns-messageevil");
    expect(parseMediaType("application/dns-messageevil") === "application/dns-message").toBe(false);
  });
});

describe("acceptsMediaType", () => {
  it("treats an absent Accept as acceptable (RFC 8484: SHOULD, not MUST)", () => {
    expect(acceptsMediaType("", "application/dns-message")).toBe(true);
    expect(acceptsMediaType(undefined, "application/dns-message")).toBe(true);
  });

  it("honors wildcards", () => {
    expect(acceptsMediaType("*/*", "application/dns-message")).toBe(true);
    expect(acceptsMediaType("application/*", "application/dns-message")).toBe(true);
    expect(acceptsMediaType("text/html, */*", "application/dns-message")).toBe(true);
  });

  it("rejects when the type is absent from Accept", () => {
    expect(acceptsMediaType("text/html", "application/dns-message")).toBe(false);
    expect(acceptsMediaType("application/json", "application/dns-message")).toBe(false);
  });

  it("accepts the exact type with parameters", () => {
    expect(acceptsMediaType("application/dns-message; charset=utf-8", "application/dns-message")).toBe(true);
  });

  it("does NOT match a prefix of the type", () => {
    expect(acceptsMediaType("application/dns-messageevil", "application/dns-message")).toBe(false);
  });

  it("q=0 on the exact type overrides a wildcard (specificity wins)", () => {
    expect(acceptsMediaType("application/dns-message;q=0, */*;q=1", "application/dns-message")).toBe(false);
    expect(acceptsMediaType("application/dns-message;q=0", "application/dns-message")).toBe(false);
  });

  it("q>0 on the exact type wins over a q=0 wildcard", () => {
    expect(acceptsMediaType("*/*;q=0, application/dns-message;q=1", "application/dns-message")).toBe(true);
  });

  it("parses q-values with decimals", () => {
    expect(acceptsMediaType("application/dns-message;q=0.5", "application/dns-message")).toBe(true);
    expect(acceptsMediaType("application/dns-message;q=0.0", "application/dns-message")).toBe(false);
  });

  it("defaults to q=1 when absent", () => {
    expect(acceptsMediaType("application/dns-message", "application/dns-message")).toBe(true);
  });

  it("ignores non-q parameters", () => {
    expect(acceptsMediaType('application/dns-message; foo="bar"', "application/dns-message")).toBe(true);
  });
});
