import { decodeJwt, importPKCS8, SignJWT } from "jose";
import type { AuthProvider, BaseAuthProvider } from "./auth_provider";
import { exception, fetchWithResult } from "gw-result";

export class AppleAuth implements AuthProvider {
  provider = "apple";

  thirdpartyAuth: BaseAuthProvider;
  appleAuthKey: string;
  appleClientId: string;
  appleTeamId: string;
  appleKeyId: string;
  appleServiceId: string;

  constructor({
    thirdpartyAuth,
    appleAuthKey,
    appleClientId,
    appleTeamId,
    appleKeyId,
    appleServiceId,
  }: {
    thirdpartyAuth: BaseAuthProvider;
    appleAuthKey: string;
    appleClientId: string;
    appleTeamId: string;
    appleKeyId: string;
    appleServiceId: string;
  }) {
    this.thirdpartyAuth = thirdpartyAuth;
    this.appleAuthKey = appleAuthKey;
    this.appleClientId = appleClientId;
    this.appleTeamId = appleTeamId;
    this.appleKeyId = appleKeyId;
    this.appleServiceId = appleServiceId;
  }

  async login(code: string, type: "web" | "app" = "app") {
    const url = "https://appleid.apple.com/auth/token";

    const client_secret = await this.generateAppleClientSecret(type);

    const fetchResult = await fetchWithResult(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        client_id: type === "web" ? this.appleServiceId : this.appleClientId,
        client_secret,
        code,
        grant_type: "authorization_code",
      }),
    });

    if (fetchResult.isErr) {
      return fetchResult;
    }

    const res = fetchResult.value;

    if (!res.ok) {
      console.error(await res.text());

      return exception("APPLE_AUTH_FAILED", "애플 인증에 실패했습니다.");
    }

    const data = await res.json();

    const { id_token } = data;

    const appleAuth = decodeJwt(id_token);

    const { sub, email, name } = appleAuth as any;

    const payload = {
      id: sub,
      email,
      name,
    };

    return this.thirdpartyAuth.issueTokensIfUserFound("apple", payload);
  }

  private async generateAppleClientSecret(type: "web" | "app" = "web") {
    const clientId = type === "web" ? this.appleServiceId : this.appleClientId;

    const keyObject = await importPKCS8(this.appleAuthKey, "ES256");

    return new SignJWT()
      .setProtectedHeader({ alg: "ES256", kid: this.appleKeyId })
      .setIssuedAt()
      .setIssuer(this.appleTeamId)
      .setExpirationTime("1h")
      .setAudience("https://appleid.apple.com")
      .setSubject(clientId)
      .sign(keyObject);
  }
}
