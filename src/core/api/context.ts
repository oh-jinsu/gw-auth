import type { SessionAuthService } from "../session/session_auth_service";
import type { SessionUserRepository } from "../session/session_repository";
import type { BrowserCookies } from "./browser_cookie";

/** Internal dependencies shared by every configured authentication feature. */
export type AuthContext<TClaims extends Record<string, unknown>> = {
  sessions: SessionAuthService<TClaims>;
  users: SessionUserRepository<TClaims>;
  cookies: BrowserCookies;
};
