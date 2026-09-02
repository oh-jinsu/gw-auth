import {
  createAuth,
  type AuthState,
  type AuthSessionRepository,
  type OAuthTransactionRepository,
  type PasswordRepository,
  type SocialRepository,
} from "../src/core";
import {
  createAuthRoute,
  getAuth,
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

/** Application-owned claims used to exercise generic public contracts. */
type ApplicationClaims = {
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
const mobileOnlySocial = auth.social({ repository: socialRepository });
const authRoute = createAuthRoute({
  siteOrigin: "https://example.test",
  session: auth.session,
  password: auth.password({ repository: passwordRepository }),
  social: {
    signup: social.signup,
    google: social.google({
      clientId: "google-client",
      clientSecret: "google-secret",
    }),
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
void authRoute.GET;
void authRoute.POST;

const loginRoute = routeHandler(async () => browserPassword.login({
  id: "member",
  password: "secret",
}));

/** Exercises the Server Action adapter with a core browser operation. */
async function loginAction() {
  return serverAction(() => browserPassword.login({ id: "member", password: "secret" }));
}

void loginRoute;
void loginAction;
void authRequest<AuthState<ApplicationClaims>>("/auth/login");
void withAuth(auth.session.browser(), async (_request, _event, currentAuth) => {
  return Response.json({ authenticated: currentAuth !== undefined });
});
void getAuth(auth.session.browser());
void AuthProvider<ApplicationClaims>;
void useAuth<ApplicationClaims>;
void startOAuth;
