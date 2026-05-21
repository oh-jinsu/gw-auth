export type AccessTokenPayload = {
  userId: string;
  role: string;
  name: string;
  iat: number;
  exp: number;
};

export type RefreshTokenPayload = {
  userId: string;
  role: string;
  name: string;
  iat: number;
  exp: number;
};
