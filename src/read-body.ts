// Bounded incremental body reading. Both directions of the proxy need the
// same guarantee: a body without a truthful Content-Length (chunked request,
// streamed upstream response) must never be fully buffered before the size
// cap applies. Chunks are accumulated and the read aborts (and the stream is
// cancelled) the moment the cap is exceeded. Returns null when the stream
// overruns `maxBytes`.

export async function readStreamBounded(
  stream: ReadableStream<Uint8Array> | null,
  maxBytes: number,
): Promise<Uint8Array<ArrayBuffer> | null> {
  if (!stream) return new Uint8Array(0);
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {}); // tell the sender to stop
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const out = new Uint8Array(total);
  let o = 0;
  for (const chunk of chunks) {
    out.set(chunk, o);
    o += chunk.byteLength;
  }
  return out;
}

/**
 * Cancels an unconsumed response body so the socket is released promptly.
 * Rejecting a response without consuming or cancelling it (wrong status,
 * wrong Content-Type, ...) leaves the connection open until GC reclaims it —
 * a leak that accumulates on a long-lived serverless instance whenever an
 * upstream misbehaves.
 */
export async function discardBody(res: Response): Promise<void> {
  try {
    await res.body?.cancel();
  } catch {
    // already consumed, errored or cancelled — nothing left to release
  }
}
