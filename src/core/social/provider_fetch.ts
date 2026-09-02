import { fetchWithResult } from "gw-result";

const providerRequestTimeoutMs = 10_000;

/** Calls an authentication provider with a bounded default network timeout. */
export function providerFetch(input: RequestInfo | URL, init: RequestInit = {}) {
  const signal = init.signal ?? AbortSignal.timeout(providerRequestTimeoutMs);

  return fetchWithResult(input, { ...init, signal });
}
