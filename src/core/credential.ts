import { ok, resultFrom } from "gw-result";

import { authSystemError } from "./auth_error";

const credentialBytes = 32;

/** Creates a URL-safe high-entropy bearer credential using the platform CSPRNG. */
export function randomCredential() {
  const bytes = crypto.getRandomValues(new Uint8Array(credentialBytes));

  return Buffer.from(bytes).toString("base64url");
}

/** Hashes every byte of a high-entropy credential before persistence. */
export async function hashCredential(credential: string) {
  const digest = await resultFrom(() =>
    crypto.subtle.digest("SHA-256", new TextEncoder().encode(credential)),
  );

  if (digest.isErr) {
    return authSystemError("credential_hash", digest.error);
  }

  const hash = Buffer.from(digest.value).toString("hex");

  return ok(hash);
}

/** Checks the expected encoding and entropy length of an opaque credential. */
export function isCredential(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
}
