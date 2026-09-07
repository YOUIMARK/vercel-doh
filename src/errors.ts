// Error response builders. For DoH we prefer a real dns-message with SERVFAIL
// so standard clients can match it to their pending query.

import { buildErrorResponse } from "./dns/wire.js";

const DNS_MESSAGE = "application/dns-message";

export const SERVFAIL_RCODE = 2;

/** A minimal valid dns-message response with RCODE=SERVFAIL, echoing the query ID + question. */
export function servfailResponse(
  query: Uint8Array<ArrayBuffer> | null,
  headers?: Record<string, string>,
): Response {
  const body = buildErrorResponse(query, SERVFAIL_RCODE);
  const h = new Headers(headers);
  h.set("Content-Type", DNS_MESSAGE);
  h.set("Cache-Control", "no-store");
  return new Response(body, { status: 200, headers: h });
}

export function textError(
  status: number,
  message: string,
  headers?: Record<string, string>,
): Response {
  const h = new Headers(headers);
  h.set("Content-Type", "text/plain; charset=utf-8");
  h.set("Cache-Control", "no-store");
  return new Response(message, { status, headers: h });
}

export function corsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Accept",
    "Access-Control-Max-Age": "86400",
  };
}
