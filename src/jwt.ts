import { jwtVerify, importJWK, type JWTPayload } from "jose";
import type { Jwks, JwksKey } from "./jwks";

export interface AccessTokenClaims extends JWTPayload {
  sub: string;
  has_active_subscription?: boolean;
  role_claim?: string;
  email?: string;
}

export async function verifyAccessToken(
  token: string,
  jwks: Jwks
): Promise<AccessTokenClaims> {
  const { payload } = await jwtVerify(token, async (header) => {
    const key = jwks.keys.find((k: JwksKey) => k.kid === header.kid);
    if (!key) {
      throw new Error(`No matching JWKS key for kid=${header.kid}`);
    }
    return importJWK(key, header.alg ?? "RS256");
  });
  return payload as AccessTokenClaims;
}
