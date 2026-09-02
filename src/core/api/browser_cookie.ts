/** SameSite values supported by framework-neutral browser cookie mutations. */
export type BrowserCookieSameSite = "strict" | "lax" | "none";

/** Optional name and policy overrides for one security-sensitive cookie. */
export type BrowserCookieOptions = {
  name?: string;
  domain?: string;
  path?: string;
  secure?: boolean;
  sameSite?: BrowserCookieSameSite;
};

/** Browser cookie configuration accepted once by `createAuth`. */
export type BrowserCookiesOptions = {
  accessToken?: BrowserCookieOptions;
  refreshToken?: BrowserCookieOptions;
  oauthState?: BrowserCookieOptions;
  socialSignup?: BrowserCookieOptions;
  guest?: BrowserCookieOptions;
};

/** Cookie values parsed by a consuming application or framework adapter. */
export type BrowserCookieValues = Readonly<Record<string, string | undefined>>;

/** Framework-neutral instruction to create or replace one browser cookie. */
export type SetBrowserCookie = ResolvedBrowserCookie & {
  operation: "set";
  value: string;
  expiresAt?: number;
};

/** Framework-neutral instruction to remove one browser cookie. */
export type DeleteBrowserCookie = ResolvedBrowserCookie & {
  operation: "delete";
};

/** Cookie operation applied by a consuming application or external adapter. */
export type BrowserCookieMutation = SetBrowserCookie | DeleteBrowserCookie;

/** Fully resolved browser cookie policy retained by the auth facade. */
export type ResolvedBrowserCookie = {
  name: string;
  domain?: string;
  path: string;
  httpOnly: true;
  secure: boolean;
  sameSite: BrowserCookieSameSite;
};

/** Resolved cookies used by every browser authentication feature. */
export type BrowserCookies = {
  accessToken: ResolvedBrowserCookie;
  refreshToken: ResolvedBrowserCookie;
  oauthState: ResolvedBrowserCookie;
  socialSignup: ResolvedBrowserCookie;
  guest: ResolvedBrowserCookie;
};

/** Resolves service-prefixed safe defaults once at the package composition root. */
export function resolveBrowserCookies(
  serviceName: string,
  options: BrowserCookiesOptions = {},
): BrowserCookies {
  const prefix = `${serviceName}_`;

  return {
    accessToken: resolveCookie(`${prefix}access_token`, options.accessToken),
    refreshToken: resolveCookie(`${prefix}refresh_token`, options.refreshToken),
    oauthState: resolveCookie(`${prefix}oauth_state`, options.oauthState, "none"),
    socialSignup: resolveCookie(`${prefix}social_signup`, options.socialSignup),
    guest: resolveCookie(`${prefix}guest_credential`, options.guest),
  };
}

/** Reads a configured cookie from values already parsed by the caller. */
export function readBrowserCookie(
  values: BrowserCookieValues,
  cookie: ResolvedBrowserCookie,
) {
  const value = values[cookie.name];

  return typeof value === "string" && value !== "" ? value : undefined;
}

/** Creates a framework-neutral cookie-set instruction. */
export function setBrowserCookie(
  cookie: ResolvedBrowserCookie,
  value: string,
  expiresAt?: Date,
): SetBrowserCookie {
  return {
    ...cookie,
    operation: "set",
    value,
    expiresAt: expiresAt?.getTime(),
  };
}

/** Creates a framework-neutral cookie-deletion instruction. */
export function deleteBrowserCookie(cookie: ResolvedBrowserCookie): DeleteBrowserCookie {
  return { ...cookie, operation: "delete" };
}

/** Applies package defaults without allowing HttpOnly to be disabled. */
function resolveCookie(
  defaultName: string,
  options: BrowserCookieOptions = {},
  defaultSameSite: BrowserCookieSameSite = "lax",
): ResolvedBrowserCookie {
  return {
    name: options.name ?? defaultName,
    domain: options.domain,
    path: options.path ?? "/",
    httpOnly: true,
    secure: options.secure ?? true,
    sameSite: options.sameSite ?? defaultSameSite,
  };
}
