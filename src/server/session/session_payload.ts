import type { JWTPayload } from "jose";

export type SessionAccessPayload = JWTPayload & {
  userId: string;
  role: string;
  name: string;
};

export type SessionRefreshPayload = SessionAccessPayload & {
  sessionId: string;
  jti: string;
};
