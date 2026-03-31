export type AccessTokenPayload = { userId: string; role: string; name: string };

export type RefreshTokenPayload = {
  userId: string;
  role: string;
  name: string;
};
