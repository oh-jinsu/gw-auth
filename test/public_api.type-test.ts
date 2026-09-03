import {
  authErrorCategory,
  authStateFromAccessPayload,
  createAuth,
  type AccountDeletionRepository,
  type AuthState,
  type AuthSessionRepository,
  type OAuthTransactionRepository,
  type PasswordRepository,
  type SocialRepository,
} from "../src/core";
import {
  createAuthResolver,
  createAuthRoute,
  getAuth,
  getAuthWithRefresh,
  routeHandler,
  serverAction,
  withAuth,
} from "../src/nextjs";
import {
  AuthProvider,
  authRequest,
  startOAuth,
  useAuth,
} from "../src/nextjs/client";
import {
  assertOAuthTransactionRepositoryConformance,
  assertAccountDeletionRepositoryConformance,
  assertPasswordResetRepositoryConformance,
  assertSessionRepositoryConformance,
  assertSocialRepositoryConformance,
} from "../src/testing";

/** Application-owned claims used to exercise generic public contracts. */
type ApplicationClaims = {
  nbf: number;
  permissions: string[];
};

/** Application-owned password registration fields. */
type PasswordRegistration = {
  displayName: string;
};

/** Application-owned social registration fields. */
type SocialRegistration = {
  gender: "female" | "male" | "other";
};

declare const sessions: AuthSessionRepository<ApplicationClaims>;
declare const accountDeletionRepository: AccountDeletionRepository;
declare const passwordRepository: PasswordRepository<PasswordRegistration, ApplicationClaims>;
declare const socialRepository: SocialRepository<SocialRegistration, ApplicationClaims>;
declare const oauthTransactions: OAuthTransactionRepository;

const auth = createAuth<ApplicationClaims>({
  serviceName: "type-test",
  sessions,
  tokens: {
    access: {
      secret: "0123456789abcdef0123456789abcdef",
      expiresIn: "15m",
    },
    refresh: {
      secret: "fedcba9876543210fedcba9876543210",
      expiresIn: "30d",
    },
  },
  browser: {
    cookies: {
      accessToken: { name: "auth_access" },
      refreshToken: { name: "auth_refresh" },
    },
  },
});

const browserPassword = auth.password({ repository: passwordRepository }).browser();
const mobilePassword = auth.password({ repository: passwordRepository }).mobile();
const social = auth.social({
  repository: socialRepository,
  transactions: oauthTransactions,
});
const browserGoogle = social.google({
  clientId: "google-client",
  clientSecret: "google-secret",
}).browser({ redirectUri: "https://example.test/auth/google/callback" });
const mobileGoogle = social.google({ clientId: "google-client" }).mobile();
const appleOptions = {
  authKey: "apple-auth-key",
  teamId: "apple-team",
  keyId: "apple-key",
};
const apple = social.apple({
  ...appleOptions,
});
const account = auth.account({
  repository: accountDeletionRepository,
  providers: { apple },
});
const browserApple = apple.browser({
  serviceId: "apple-service",
  redirectUri: "https://example.test/auth/apple/callback",
}).web();
const androidApple = apple.browser({
  serviceId: "apple-service",
  redirectUri: "https://example.test/api/auth/mobile/apple/callback",
}).android({ packageId: "com.example.app" });
const unprojectedAndroidApple = apple.browser({
  serviceId: "apple-service",
  redirectUri: "https://example.test/api/auth/mobile/apple/callback",
});

// @ts-expect-error Flutter Android requires its callback Activity package identifier.
unprojectedAndroidApple.android();
const iosApple = apple.native({ appId: "com.example.app" }).ios();
// @ts-expect-error Apple signing configuration no longer accepts a client selector.
social.apple({ ...appleOptions, clientId: "apple-client" });
// @ts-expect-error Apple selects its Browser or Native API before delivery.
apple.mobile();
const mobileOnlySocial = auth.social({ repository: socialRepository });
const authRoute = createAuthRoute({
  siteOrigin: "https://example.test",
  session: auth.session,
  account,
  password: auth.password({ repository: passwordRepository }),
  social: {
    signup: social.signup,
    google: {
      feature: social.google({
        clientId: "google-client",
        clientSecret: "google-secret",
      }),
      browser: true,
      mobile: { clientIds: ["google-ios", "google-android"] },
    },
    apple: {
      feature: apple,
      web: { serviceId: "apple-service" },
      android: {
        serviceId: "apple-service",
        packageId: "com.example.app",
      },
      ios: { appId: "com.example.app" },
    },
  },
});

void browserPassword.login({ id: "member", password: "secret" });
void mobilePassword.signup({
  id: "member",
  password: "secret",
  passwordConfirm: "secret",
  registration: { displayName: "Member" },
});
void browserGoogle.start({ redirectPath: "/settings" });
void browserGoogle.complete({
  code: "provider-code",
  state: "state",
  cookies: { "type-test_oauth_state": "state" },
});
void mobileGoogle.login({ idToken: "google-id-token" });
void browserApple.start();
void androidApple.start();
void androidApple.complete({ authorizationCode: "apple-code", state: "apple-state" });
void androidApple.handoff({ code: "apple-code", state: "apple-state" });
void iosApple.login({ authorizationCode: "apple-code" });
void apple.revoke({
  providerClientId: "com.example.app",
  providerRefreshToken: "apple-refresh-token",
});
void account.browser().delete({ cookies: { "type-test_access_token": "access-token" } });
void account.mobile().delete({ accessToken: "access-token" });
void account.retryPending("pending-user-id");
// @ts-expect-error Revocation must use the base Apple feature with its stored client ID.
iosApple.revoke({ providerRefreshToken: "apple-refresh-token" });
void mobileOnlySocial.kakao().mobile().login({ accessToken: "kakao-access-token" });
void social.signup.browser().complete({
  cookies: { "type-test_social_signup": "signup-token" },
  registration: { gender: "other" },
});

const authState: AuthState<ApplicationClaims> = {
  userId: crypto.randomUUID(),
  sessionId: crypto.randomUUID(),
  permissions: ["profile:read"],
};

void authState;
void authStateFromAccessPayload;
void authErrorCategory;
// @ts-expect-error JWT-managed claims are never part of public authentication state.
authState.nbf;
void authRoute.GET;
void authRoute.POST;

const loginRoute = routeHandler(async () => browserPassword.login({
  id: "member",
  password: "secret",
}));
const mobileLoginRoute = routeHandler(async () => mobilePassword.login({
  id: "member",
  password: "secret",
}));

/** Exercises the Server Action adapter with a core browser operation. */
async function loginAction() {
  return serverAction(() => browserPassword.login({ id: "member", password: "secret" }));
}

/** Exercises a cookie-free mobile result through the same Server Action adapter. */
async function mobileLoginAction() {
  return serverAction(() => mobilePassword.login({ id: "member", password: "secret" }));
}

void loginRoute;
void mobileLoginRoute;
void loginAction;
void mobileLoginAction;
void authRequest<AuthState<ApplicationClaims>>("/auth/login");
void withAuth(auth.session.browser(), async (_request, _event, currentAuth) => {
  return Response.json({ authenticated: currentAuth !== undefined });
});
void getAuth(auth.session.browser());
void getAuthWithRefresh(auth.session.browser());

const authResolver = createAuthResolver(auth.session);

void authResolver.cookies({ refresh: false });
void authResolver.cookies();
void authResolver.request();

/** Verifies that Next.js server auth returns normalized browser-safe state. */
async function inspectServerAuth() {
  const current = await getAuth(auth.session.browser());

  if (current.isOk) {
    current.value.permissions;
    // @ts-expect-error JWT-managed claims are absent from normalized getAuth state.
    current.value.nbf;
  }
}

/** Verifies that mutable request auth returns normalized browser-safe state. */
async function inspectRefreshedServerAuth() {
  const current = await getAuthWithRefresh(auth.session.browser());

  if (current.isOk) {
    current.value.permissions;
    // @ts-expect-error JWT-managed claims are absent from normalized refreshed auth state.
    current.value.nbf;
  }
}

/** Verifies that request auth returns one normalized state for either transport. */
async function inspectRequestAuth() {
  const current = await authResolver.request();

  if (current.isOk) {
    current.value.permissions;
    // @ts-expect-error JWT-managed claims are absent from normalized request auth state.
    current.value.nbf;
  }
}

void inspectServerAuth;
void inspectRefreshedServerAuth;
void inspectRequestAuth;
void AuthProvider<ApplicationClaims>;
void useAuth<ApplicationClaims>;
void startOAuth;
void assertSessionRepositoryConformance;
void assertAccountDeletionRepositoryConformance;
void assertOAuthTransactionRepositoryConformance;
void assertSocialRepositoryConformance;
void assertPasswordResetRepositoryConformance;
