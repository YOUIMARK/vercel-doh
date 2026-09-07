// Hono application assembly. Entrypoint for both Vercel (index.ts re-export)
// and local dev (src/dev.ts).

import { Hono } from "hono";
import { loadConfig, type DoHConfig } from "./config";
import { handleDnsQuery } from "./routes/dns-query";
import { handleJsonQuery } from "./routes/json";
import { homePage, health } from "./routes/home";

export function createApp(config: DoHConfig = loadConfig()): Hono {
  const app = new Hono();
  const base = config.dohPath;

  app.get("/", homePage(config));
  app.get("/health", health());

  // DoH endpoints mounted at the configured base path (default /dns-query).
  // When DOH_PATH is customized, the standard /dns-query endpoints are NOT
  // registered, so the old path returns 404 (path obfuscation).
  app.all(base, handleDnsQuery(config, "default"));
  app.all(`${base}/auto_ecs`, handleDnsQuery(config, "force_enable"));
  app.all(`${base}/no_ecs`, handleDnsQuery(config, "force_disable"));
  // {base}/{provider} — optional path-based provider mapping
  app.all(`${base}/*`, handleDnsQuery(config, "default"));

  // dns-json API for the web tool (fixed public path).
  app.all("/dns-query-json", handleJsonQuery(config));

  return app;
}

export const app = createApp();
export default app;
