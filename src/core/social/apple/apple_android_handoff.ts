import { ok } from "gw-result";

import type { AuthResult } from "../../api/auth_result";
import { authError } from "../../auth_error";

const callbackKeys = [
  "code",
  "id_token",
  "state",
  "user",
  "error",
  "error_description",
] as const;
const maximumCallbackValueLength = 8192;

/** Android application package used by Flutter's Apple callback Activity. */
export type AppleAndroidOptions = {
  packageId: string;
};

/** Untrusted Apple form-post values parsed by an external HTTP adapter. */
export type AppleAndroidHandoffInput = Readonly<Record<string, string | undefined>>;

/** Validated Flutter callback destination created from Apple's original fields. */
export type AppleAndroidHandoffOutput = {
  redirectUrl: string;
};

/** Validates Apple's callback and creates Flutter's exact callback Intent. */
export function appleAndroidHandoff(
  packageId: string,
  input: AppleAndroidHandoffInput,
): AuthResult<AppleAndroidHandoffOutput> {
  const parameters = callbackParameters(input);
  const validState = parameters.has("state");
  const validOutcome = parameters.has("code") || parameters.has("error");

  return validState && validOutcome
    ? ok({ redirectUrl: androidIntent(packageId, parameters) })
    : invalidAppleCallback();
}

/** Rejects package identifiers that could alter the generated Android Intent. */
export function assertAppleAndroidPackageId(packageId: string) {
  const segment = "[A-Za-z][A-Za-z0-9_]*";
  const packagePattern = new RegExp(`^${segment}(\\.${segment})+$`);

  if (!packagePattern.test(packageId)) {
    throw new TypeError("Apple Android packageId is invalid.");
  }
}

/** Selects nonempty bounded callback values without forwarding unrelated fields. */
function callbackParameters(input: AppleAndroidHandoffInput) {
  const parameters = new URLSearchParams();

  for (const key of callbackKeys) {
    const value = input[key];
    const valid = typeof value === "string"
      && value.length > 0
      && value.length <= maximumCallbackValueLength;

    if (valid) {
      parameters.set(key, value);
    }
  }

  return parameters;
}

/** Builds the exact Intent URI consumed by Flutter's sign_in_with_apple plugin. */
function androidIntent(packageId: string, parameters: URLSearchParams) {
  return `intent://callback?${parameters.toString()}`
    + `#Intent;package=${packageId};scheme=signinwithapple;end`;
}

/** Returns one stable failure for a malformed Apple callback. */
function invalidAppleCallback() {
  return authError("INVALID_OAUTH_RESPONSE", "Apple 인증 응답이 유효하지 않습니다.");
}
