// Minimal logger. DNS query content is never logged unless DEBUG_LOGGING is on.

let debugEnabled = false;

export function setDebugLogging(enabled: boolean): void {
  debugEnabled = enabled;
}

export function debugLog(...args: unknown[]): void {
  if (debugEnabled) console.log("[doh]", ...args);
}

export function errorLog(...args: unknown[]): void {
  console.error("[doh]", ...args);
}
