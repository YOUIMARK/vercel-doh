import { describe, expect, it } from "vitest";
import { loadConfig, parseDohPath } from "../src/config";

describe("parseDohPath", () => {
  it("defaults to /dns-query", () => {
    expect(parseDohPath(undefined)).toBe("/dns-query");
    expect(parseDohPath("")).toBe("/dns-query");
  });

  it("accepts a single obfuscated segment", () => {
    expect(parseDohPath("/3f9a2b7c8d1e4f5a")).toBe("/3f9a2b7c8d1e4f5a");
    expect(parseDohPath("/dns-2026_x")).toBe("/dns-2026_x");
  });

  it("rejects malformed paths", () => {
    for (const bad of ["dns-query", "/a/b", "/a b", "/a?b", "//", "/", "/a#b", "/a%b"]) {
      expect(() => parseDohPath(bad), bad).toThrow();
    }
  });
});

describe("loadConfig", () => {
  it("reads DOH_PATH from env", () => {
    const cfg = loadConfig({ DOH_PATH: "/my-secret-42" } as NodeJS.ProcessEnv);
    expect(cfg.dohPath).toBe("/my-secret-42");
  });

  it("keeps defaults when env is empty", () => {
    const cfg = loadConfig({} as NodeJS.ProcessEnv);
    expect(cfg.dohPath).toBe("/dns-query");
    expect(cfg.upstreamUrls).toEqual(["https://cloudflare-dns.com/dns-query"]);
    expect(cfg.autoAddEcs).toBe(false);
    expect(cfg.cacheMaxAge).toBe(300);
  });
});

describe("strict numeric parsing", () => {
  it("rejects dirty numeric values instead of truncating", () => {
    for (const dirty of ["3000foo", "24.9", "12abc", "-5", "0x10", "1e3"]) {
      expect(() => loadConfig({ CACHE_MAX_AGE: dirty } as NodeJS.ProcessEnv), dirty).toThrow();
    }
  });

  it("accepts clean integers within range", () => {
    expect(loadConfig({ CACHE_MAX_AGE: "120" } as NodeJS.ProcessEnv).cacheMaxAge).toBe(120);
    expect(loadConfig({ UPSTREAM_TIMEOUT_MS: "2500" } as NodeJS.ProcessEnv).upstreamTimeoutMs).toBe(2500);
  });
});

describe("DOMAIN_MAPPINGS validation", () => {
  it("accepts bare hosts and https URLs", () => {
    const cfg = loadConfig({
      DOMAIN_MAPPINGS: JSON.stringify({ google: { targetDomain: "dns.google" } }),
    } as NodeJS.ProcessEnv);
    expect(cfg.domainMappings.google!.targetDomain).toBe("dns.google");
  });

  it("rejects non-https schemes", () => {
    for (const target of ["http://dns.google", "ftp://x", "file:///etc/passwd"]) {
      expect(
        () =>
          loadConfig({
            DOMAIN_MAPPINGS: JSON.stringify({ bad: { targetDomain: target } }),
          } as NodeJS.ProcessEnv),
        target,
      ).toThrow();
    }
  });

  it("rejects garbage JSON", () => {
    expect(() => loadConfig({ DOMAIN_MAPPINGS: "not json" } as NodeJS.ProcessEnv)).toThrow();
  });
});
