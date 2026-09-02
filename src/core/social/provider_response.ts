import { ok, resultFrom } from "gw-result";

import { authError } from "../auth_error";

/** Parses a successful provider response without logging provider tokens or bodies. */
export async function providerJson(
  response: Response,
  provider: string,
  code: string,
  message: string,
) {
  if (!response.ok) {
    return providerRequestError({ response }, provider, code, message);
  }

  const parsed = await resultFrom(() => response.json());

  return parsed.isErr
    ? invalidProviderResponse(provider, parsed.error)
    : ok(parsed.value);
}

/** Maps a failed provider request to invalid credentials or temporary unavailability. */
export function providerRequestError(
  cause: unknown,
  provider: string,
  invalidCode: string,
  invalidMessage: string,
) {
  const status = responseStatus(cause);

  return status !== undefined && !isTemporaryStatus(status)
    ? authError(invalidCode, invalidMessage, { status })
    : providerUnavailable(provider, cause);
}

/** Distinguishes remote-key transport failures from an invalid signed credential. */
export function providerVerificationError(
  cause: unknown,
  provider: string,
  invalidCode: string,
  invalidMessage: string,
) {
  return isVerificationUnavailable(cause)
    ? providerUnavailable(provider, cause)
    : authError(invalidCode, invalidMessage, cause);
}

/** Creates a retryable provider transport or upstream-service failure. */
export function providerUnavailable(provider: string, cause?: unknown) {
  return authError(
    "PROVIDER_UNAVAILABLE",
    "외부 인증 제공자를 일시적으로 사용할 수 없습니다.",
    { provider, cause },
  );
}

/** Creates a provider contract failure for a malformed successful response. */
export function invalidProviderResponse(provider: string, cause?: unknown) {
  return authError(
    "INVALID_PROVIDER_RESPONSE",
    "외부 인증 제공자의 응답 형식이 유효하지 않습니다.",
    { provider, cause },
  );
}

/** Reads an HTTP status from the structural `gw-result` fetch failure. */
function responseStatus(cause: unknown) {
  if (typeof cause !== "object" || cause === null || !("response" in cause)) {
    return undefined;
  }

  const response = cause.response;

  return response instanceof Response ? response.status : undefined;
}

/** Identifies provider responses that represent throttling or upstream failure. */
function isTemporaryStatus(status: number) {
  return status === 408 || status === 429 || status >= 500;
}

/** Recognizes network and remote-JWK timeout errors without conflating JWT rejection. */
function isVerificationUnavailable(cause: unknown) {
  const aborted = cause instanceof DOMException
    && ["AbortError", "TimeoutError"].includes(cause.name);

  if (cause instanceof TypeError || aborted) {
    return true;
  }

  return typeof cause === "object"
    && cause !== null
    && "code" in cause
    && cause.code === "ERR_JWKS_TIMEOUT";
}

/** Reads a required string field from an untrusted provider JSON object. */
export function providerString(value: unknown, key: string) {
  if (typeof value !== "object" || value === null || !(key in value)) {
    return undefined;
  }

  const field = value[key as keyof typeof value];

  return typeof field === "string" && field ? field : undefined;
}
