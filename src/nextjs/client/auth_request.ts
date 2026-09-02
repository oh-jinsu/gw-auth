"use client";

import { err, fetchWithResult, ok, resultFrom } from "gw-result";
import type { AuthResult } from "gw-auth/core";

import type { NextAuthError, NextAuthResponse } from "../result";

/** Sends a no-store, cookie-aware request to a gw-auth Next.js Route Handler. */
export async function authRequest<TValue = void>(
  input: RequestInfo | URL,
  init: RequestInit = {},
): Promise<AuthResult<TValue>> {
  const fetched = await fetchWithResult(input, requestOptions(init));

  if (fetched.isErr) {
    return clientError("AUTH_NETWORK_FAILURE", "인증 서버에 연결하지 못했습니다.", fetched.error);
  }

  const parsed = await resultFrom(() => fetched.value.json() as Promise<unknown>);

  return parsed.isErr
    ? clientError("INVALID_AUTH_RESPONSE", "인증 서버 응답이 유효하지 않습니다.", parsed.error)
    : parseAuthResponse<TValue>(parsed.value);
}

/** Navigates to an application-owned OAuth start Route Handler. */
export function startOAuth(href: string | URL) {
  window.location.assign(href.toString());
}

/** Enforces browser credentials and disables response caching. */
function requestOptions(init: RequestInit): RequestInit {
  return {
    ...init,
    cache: "no-store",
    credentials: init.credentials ?? "same-origin",
  };
}

/** Converts a validated adapter envelope back to the core Result contract. */
function parseAuthResponse<TValue>(value: unknown): AuthResult<TValue> {
  if (!isNextAuthResponse<TValue>(value)) {
    return clientError("INVALID_AUTH_RESPONSE", "인증 서버 응답이 유효하지 않습니다.");
  }

  return value.ok
    ? ok(value.value as TValue)
    : clientError(value.error.code, value.error.message);
}

/** Creates a structural client-side authentication failure. */
function clientError(code: string, message: string, cause?: unknown) {
  return err(new ClientAuthError(code, message, cause));
}

/** Structural auth error that avoids loading the server core in browser bundles. */
class ClientAuthError extends Error {
  /** Public discriminator shared with core authentication failures. */
  readonly kind = "GW_AUTH_ERROR" as const;

  /** Stable machine-readable client failure code. */
  readonly code: string;

  /** Creates a browser-side authentication failure with an optional local cause. */
  constructor(code: string, message: string, cause?: unknown) {
    super(message, { cause });

    this.name = "AuthError";
    this.code = code;
  }
}

/** Recognizes the success and sanitized-error shapes emitted by the adapter. */
function isNextAuthResponse<TValue>(value: unknown): value is NextAuthResponse<TValue> {
  if (!isRecord(value) || typeof value.ok !== "boolean") {
    return false;
  }

  return value.ok || isNextAuthError(value.error);
}

/** Recognizes a structurally safe authentication error response. */
function isNextAuthError(value: unknown): value is NextAuthError {
  return isRecord(value)
    && value.kind === "GW_AUTH_ERROR"
    && typeof value.code === "string"
    && typeof value.message === "string";
}

/** Narrows unknown JSON values to property-bearing records. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
