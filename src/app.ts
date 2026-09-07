// Hono application assembly. Entrypoint for both Vercel (index.ts re-export)
// and local dev (src/dev.ts).

import { Hono } from "hono";
import { loadConfig, type DoHConfig } from "./config";
import { handleDnsQuery } from "./routes/dns-query";
import { handleJsonQuery } from "./routes/json";
import { homePage, health } from "./routes/home";

export function createApp(config: DoHConfig = loadConfig()): Hono {
  const app = new Hono();

  app.get("/", homePage(config));
  app.get("/health", health());

  app.all("/dns-query", handleDnsQuery(config, "default"));
  app.all("/dns-query/auto_ecs", handleDnsQuery(config, "force_enable"));
  app.all("/dns-query/no_ecs", handleDnsQuery(config, "force_disable"));
  // /dns-query/{provider} — optional path-based provider mapping
  app.all("/dns-query/*", handleDnsQuery(config, "default"));

  app.all("/dns-query-json", handleJsonQuery(config));

  return app;
}

export const app = createApp();
export default app;
