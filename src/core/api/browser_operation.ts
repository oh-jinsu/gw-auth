import type { AuthResult } from "./auth_result";
import type { BrowserCookieMutation } from "./browser_cookie";

/** Result plus browser-cookie effects that adapters must apply on either branch. */
export type BrowserOperation<TValue> = {
  result: AuthResult<TValue>;
  cookies: readonly BrowserCookieMutation[];
};
