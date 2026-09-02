import type {
  AppleSocialAuth,
  GoogleMobileOptions,
  GoogleSocialAuth,
  GuestAuth,
  KakaoSocialAuth,
  NaverSocialAuth,
  PasswordAuth,
  PasswordRecoveryAuth,
  SessionAuth,
  SocialSignupAuth,
} from "gw-auth/core";
import type { NextRequest, NextResponse } from "next/server.js";

/** Dynamic context required by `app/api/auth/[...auth]/route.ts`. */
export type AuthRouteContext = {
  params: Promise<{ auth: string[] }>;
};

/** GET and POST methods exposed by the prebuilt authentication route. */
export type AuthRouteMethod = "GET" | "POST";

/** Next.js handler produced for one supported authentication method. */
export type AuthRouteHandler = (
  request: NextRequest,
  context: AuthRouteContext,
) => Promise<NextResponse>;

/** Route Handler exports returned by `createAuthRoute`. */
export type AuthRouteHandlers = {
  GET: AuthRouteHandler;
  POST: AuthRouteHandler;
};

/** Apple API identifiers and Android package binding enabled on the fixed route. */
export type AuthRouteApple<TClaims extends Record<string, unknown>> = {
  /** Apple feature configured with the shared signing key. */
  feature: AppleSocialAuth<TClaims>;

  /** Enables website Apple login with this Services ID. */
  web?: { serviceId: string };

  /** Enables Flutter Android Apple login with this Services ID and package. */
  android?: { serviceId: string; packageId: string };

  /** Enables native iOS Apple login with this App ID. */
  ios?: { appId: string };
};

/** Explicit delivery selection for one provider used by the fixed route. */
export type AuthRouteProvider<TFeature, TMobile = true> =
  | { feature: TFeature; browser: true; mobile?: TMobile }
  | { feature: TFeature; browser?: false; mobile: TMobile };

/** Social features and the browser/mobile deliveries enabled for each provider. */
export type AuthRouteSocial<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
> = {
  signup: SocialSignupAuth<TRegistrationInput, TClaims>;
  google?: AuthRouteProvider<GoogleSocialAuth<TClaims>, true | GoogleMobileOptions>;
  kakao?: AuthRouteProvider<KakaoSocialAuth<TClaims>>;
  naver?: AuthRouteProvider<NaverSocialAuth<TClaims>>;
  apple?: AuthRouteApple<TClaims>;
};

/** Features and trusted origin consumed by the fixed Next.js authentication route. */
export type AuthRouteOptions<
  TClaims extends Record<string, unknown>,
  TPasswordRegistration = unknown,
  TSocialRegistration = unknown,
> = {
  /** Trusted public origin used to derive fixed OAuth callback URIs. */
  siteOrigin: string;

  /** Shared session feature before browser or mobile projection. */
  session: SessionAuth<TClaims>;

  /** Optional password feature before browser or mobile projection. */
  password?: PasswordAuth<TPasswordRegistration, TClaims>;

  /** Optional guest feature before browser or mobile projection. */
  guest?: GuestAuth<TClaims>;

  /** Optional provider and staged-signup features shared by both transports. */
  social?: AuthRouteSocial<TSocialRegistration, TClaims>;

  /** Optional transport-independent password-recovery feature. */
  recovery?: PasswordRecoveryAuth;
};

/** Internal exact-path route registered by the prebuilt dispatcher. */
export type AuthRouteDefinition = {
  method: AuthRouteMethod;
  path: string;
  handler: (request: NextRequest) => Promise<NextResponse>;
  /** Allows provider-owned form-post callbacks with a foreign Origin header. */
  acceptsCrossOrigin?: boolean;
};
