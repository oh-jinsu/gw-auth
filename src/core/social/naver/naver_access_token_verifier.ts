import { fetchWithResult, ok, resultFrom } from "gw-result";

import { authError } from "../../auth_error";
import type { SocialIdentityVerifier } from "../social_identity";

/** Resolves and validates a Naver access token through Naver's profile API. */
export class NaverAccessTokenVerifier implements SocialIdentityVerifier {
  /** Verifies a Naver bearer token and normalizes its user identity. */
  async verify(accessToken: string) {
    const fetched = await fetchWithResult("https://openapi.naver.com/v1/nid/me", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (fetched.isErr || !fetched.value.ok) {
      return authError("NAVER_AUTH_FAILED", "Naver 인증에 실패했습니다.");
    }

    const parsed = await resultFrom(() => fetched.value.json());

    if (parsed.isErr || !isNaverUser(parsed.value)) {
      return authError("NAVER_AUTH_FAILED", "Naver 인증에 실패했습니다.");
    }

    return ok(naverIdentity(parsed.value.response));
  }
}

/** Minimum successful Naver profile-response shape. */
type NaverUser = {
  resultcode: string;
  response: {
    id: string;
    email?: string;
    nickname?: string;
    profile_image?: string;
  };
};

/** Validates the Naver success code and required provider-scoped identifier. */
function isNaverUser(value: unknown): value is NaverUser {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  if (!("resultcode" in value) || value.resultcode !== "00" || !("response" in value)) {
    return false;
  }

  const response = value.response;

  return typeof response === "object"
    && response !== null
    && "id" in response
    && typeof response.id === "string"
    && response.id !== "";
}

/** Converts a validated Naver profile to the canonical identity contract. */
function naverIdentity(user: NaverUser["response"]) {
  return {
    provider: "naver" as const,
    id: user.id,
    ...maybeString("email", user.email),
    ...maybeString("name", user.nickname),
    ...maybeString("picture", user.profile_image),
  };
}

/** Includes a provider field only when it contains a non-empty string. */
function maybeString(key: string, value: string | undefined) {
  return value ? { [key]: value } : {};
}
