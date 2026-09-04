import { ok, resultFrom } from "gw-result";
import { type JWTPayload, SignJWT, decodeJwt, jwtVerify } from "jose";

import { authError } from "./auth_error";

const minimumSecretBytes = 32;

/** Runtime predicate used to narrow verified JWT claims before returning them. */
export type JwtPayloadValidator<TPayload extends JWTPayload> = (
  payload: JWTPayload,
) => payload is TPayload;

/** Required configuration for a purpose-bound HMAC JWT manager. */
export type JWTManagerOptions<TPayload extends JWTPayload> = {
  secret: string;
  expiresIn: string;
  issuer: string;
  audience: string;
  tokenUse: string;
  validatePayload: JwtPayloadValidator<TPayload>;
};

/** Claims supplied by callers before managed JWT claims are added. */
export type JwtSignPayload<TPayload extends JWTPayload> = Omit<
  TPayload,
  "aud" | "exp" | "iat" | "iss" | "nbf" | "tokenUse"
>;

/** Signs and verifies one explicit JWT purpose for one issuer and audience. */
export class JWTManager<TPayload extends JWTPayload> {
  /** Expected token audience. */
  readonly audience: string;

  /** Token expiration expression accepted by `jose`. */
  readonly expiresIn: string;

  /** Expected token issuer. */
  readonly issuer: string;

  /** Expected application-level token purpose. */
  readonly tokenUse: string;

  private readonly key: Uint8Array;

  private readonly validatePayload: JwtPayloadValidator<TPayload>;

  /** Creates a manager and rejects unsafe or ambiguous token configuration. */
  constructor(options: JWTManagerOptions<TPayload>) {
    assertConfiguration(options);

    this.audience = options.audience;
    this.expiresIn = options.expiresIn;
    this.issuer = options.issuer;
    this.key = new TextEncoder().encode(options.secret);
    this.tokenUse = options.tokenUse;
    this.validatePayload = options.validatePayload;
  }

  /** Verifies signature, time, issuer, audience, purpose, and payload shape. */
  async verify(token: string) {
    const verified = await resultFrom(() =>
      jwtVerify(token, this.key, {
        algorithms: ["HS256"],
        audience: this.audience,
        issuer: this.issuer,
      }),
    );

    if (verified.isErr) {
      return authError("INVALID_TOKEN", "토큰이 유효하지 않습니다.", verified.error);
    }

    const payload = verified.value.payload;

    if (payload.tokenUse !== this.tokenUse || !this.validatePayload(payload)) {
      return authError("INVALID_TOKEN", "토큰이 유효하지 않습니다.");
    }

    return ok(payload);
  }

  /** Signs caller claims while adding all security-sensitive managed claims. */
  async sign(payload: JwtSignPayload<TPayload>) {
    const claims = { ...payload, tokenUse: this.tokenUse } as JWTPayload;
    const token = await resultFrom(() =>
      new SignJWT(claims)
        .setProtectedHeader({ alg: "HS256", typ: "JWT" })
        .setIssuedAt()
        .setIssuer(this.issuer)
        .setAudience(this.audience)
        .setExpirationTime(this.expiresIn)
        .sign(this.key),
    );

    return token.isErr
      ? authError("TOKEN_SIGNING_FAILED", "토큰을 생성하지 못했습니다.", token.error)
      : token;
  }

  /** Recreates a token with explicit timestamps from trusted persisted metadata. */
  async signAt(payload: JwtSignPayload<TPayload>, issuedAt: Date, expiresAt: Date) {
    const claims = { ...payload, tokenUse: this.tokenUse } as JWTPayload;
    const token = await resultFrom(() =>
      new SignJWT(claims)
        .setProtectedHeader({ alg: "HS256", typ: "JWT" })
        .setIssuedAt(toNumericDate(issuedAt))
        .setIssuer(this.issuer)
        .setAudience(this.audience)
        .setExpirationTime(toNumericDate(expiresAt))
        .sign(this.key),
    );

    return token.isErr
      ? authError("TOKEN_SIGNING_FAILED", "토큰을 생성하지 못했습니다.", token.error)
      : token;
  }

  /** Extracts an expiration time only for cookies created from freshly signed tokens. */
  static getExpirationTime(token: string) {
    const decoded = resultFrom(() => decodeJwt(token));

    if (decoded.isErr || typeof decoded.value.exp !== "number") {
      return authError(
        "INVALID_TOKEN_EXPIRATION",
        "토큰 만료 시간을 확인할 수 없습니다.",
        decoded.isErr ? decoded.error : undefined,
      );
    }

    return ok(new Date(decoded.value.exp * 1000));
  }
}

/** Converts a JavaScript timestamp to the integer NumericDate used by JWTs. */
function toNumericDate(value: Date) {
  return Math.floor(value.getTime() / 1000);
}

/** Validates required token-manager configuration before any token is handled. */
function assertConfiguration<TPayload extends JWTPayload>(
  options: JWTManagerOptions<TPayload>,
) {
  const secretLength = new TextEncoder().encode(options.secret).byteLength;

  if (secretLength < minimumSecretBytes) {
    throw new TypeError(`JWT secret must contain at least ${minimumSecretBytes} UTF-8 bytes.`);
  }

  if (!options.audience || !options.expiresIn || !options.issuer || !options.tokenUse) {
    throw new TypeError("JWT audience, expiration, issuer, and token use are required.");
  }
}
