import { ok, resultFrom } from "gw-result";
import { type JWTPayload, SignJWT, decodeJwt, jwtVerify } from "jose";

export class JWTManager<TPayload extends JWTPayload = JWTPayload> {
  issuer?: string;
  secret: string;
  expiresIn: string;

  constructor({
    secret,
    expiresIn = "30m",
    issuer,
  }: {
    secret: string;
    expiresIn?: string;
    issuer?: string;
  }) {
    this.secret = secret;
    this.expiresIn = expiresIn;
    this.issuer = issuer;
  }

  async verify(token: string) {
    const result = await resultFrom(() =>
      jwtVerify(token, new TextEncoder().encode(this.secret), {
        issuer: this.issuer,
      }),
    );

    if (result.isErr) {
      return result;
    }

    return ok(result.value.payload as TPayload);
  }

  async sign(payload: Omit<TPayload, "iat" | "exp">) {
    let builder = new SignJWT(payload)
      .setProtectedHeader({ alg: "HS256", typ: "JWT" })
      .setIssuedAt();

    if (this.issuer) {
      builder = builder.setIssuer(this.issuer);
    }

    builder = builder.setExpirationTime(this.expiresIn);

    return await resultFrom(() =>
      builder.sign(new TextEncoder().encode(this.secret)),
    );
  }

  decode(token: string) {
    return decodeJwt(token) as TPayload;
  }

  static getExpirationTime(token: string) {
    return new Date(Number(decodeJwt(token).exp) * 1000);
  }
}
