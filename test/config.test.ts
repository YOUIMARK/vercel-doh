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
