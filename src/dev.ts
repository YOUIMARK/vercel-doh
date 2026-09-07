// Local development server (npm run dev / npm start).
// Uses the exact same Hono app that Vercel deploys, plus static assets
// from public/ (on Vercel those are served by the CDN instead).

import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";
import { Hono } from "hono";
import app from "./app.js";

const devApp = new Hono();
devApp.use("/style.css", serveStatic({ root: "./public" }));
devApp.use("/script.js", serveStatic({ root: "./public" }));
devApp.route("/", app);

const port = Number(process.env.PORT ?? 3000);
console.log(`vercel-doh listening on http://localhost:${port}`);

serve({ fetch: devApp.fetch, port });
