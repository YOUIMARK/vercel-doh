// Hono application assembly. Entrypoint for both Vercel (index.ts re-export)
// and local dev (src/dev.ts).

import { Hono } from "hono";
import { loadConfig, type DoHConfig } from "./config.js";
import { handleDnsQuery } from "./routes/dns-query.js";
import { handleDohProxy } from "./routes/proxy.js";
import { homePage, health } from "./routes/home.js";

export function createApp(config: DoHConfig = loadConfig()): Hono {
  const app = new Hono();
  const base = config.dohPath;

  app.get("/", homePage(config));
  app.get("/health", health());

  // DoH endpoints mounted at the configured base path (default /dns-query).
  // When DOH_PATH is customized, the standard /dns-query endpoints are NOT
  // registered, so the old path returns 404 (path obfuscation).
  // Path suffixes after the base are parsed as flags/provider:
  //   {base}, {base}/v4, {base}/v6, {base}/ecs, {base}/no-ecs,
  //   {base}/{provider}, and combinations like {base}/v4/ecs.
  // The dns-json API for the web tool lives on the SAME base path: a GET
  // with ?name= (and no ?dns=) on {base} or {base}/{flags} is dispatched to
  // handleJsonQuery inside the DoH handler — one path serves both protocols
  // (dns.google/resolve style). No separate -json endpoint exists.
  app.all(`${base}`, handleDnsQuery(config, "default"));
  app.all(`${base}/*`, handleDnsQuery(config, "default"));

  // Server-side query proxy for third-party DoH providers selected in the
  // web tool (CF-Workers-DoH behavior: the server queries the provider so
  // the browser never hits CORS walls).
  app.all("/dns-query-proxy", handleDohProxy(config));
  app.all("/dns-query-proxy/*", handleDohProxy(config));

  return app;
}

export const app = createApp();
export default app;
