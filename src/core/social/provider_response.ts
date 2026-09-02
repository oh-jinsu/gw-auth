import { ok, resultFrom } from "gw-result";

import { authError } from "../auth_error";

/** Parses a successful provider response without logging provider tokens or bodies. */
export async function providerJson(
  response: Response,
  code: string,
  message: string,
) {
  if (!response.ok) {
    return authError(code, message, { status: response.status });
  }

  const parsed = await resultFrom(() => response.json());

  return parsed.isErr
    ? authError(code, message, parsed.error)
    : ok(parsed.value);
}

/** Reads a required string field from an untrusted provider JSON object. */
export function providerString(value: unknown, key: string) {
  if (typeof value !== "object" || value === null || !(key in value)) {
    return undefined;
  }

  const field = value[key as keyof typeof value];

  return typeof field === "string" && field ? field : undefined;
}
