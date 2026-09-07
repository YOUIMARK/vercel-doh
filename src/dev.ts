// Local development server (npm run dev / npm start).
// Uses the exact same Hono app that Vercel deploys.

import { serve } from "@hono/node-server";
import app from "./app";

const port = Number(process.env.PORT ?? 3000);
console.log(`vercel-doh listening on http://localhost:${port}`);

serve({ fetch: app.fetch, port });
