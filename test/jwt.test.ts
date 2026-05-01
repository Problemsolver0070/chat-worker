import { describe, expect, it, beforeAll } from "vitest";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { verifyAccessToken } from "../src/jwt";

let publicJwk: any;
let signJwt: (claims: Record<string, unknown>) => Promise<string>;

beforeAll(async () => {
  const { publicKey, privateKey } = await generateKeyPair("RS256", { extractable: true });
  publicJwk = await exportJWK(publicKey);
  publicJwk.kid = "test-key";
  publicJwk.alg = "RS256";
  publicJwk.use = "sig";
  signJwt = async (claims) =>
    new SignJWT(claims)
      .setProtectedHeader({ alg: "RS256", kid: "test-key" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(privateKey);
});

describe("verifyAccessToken", () => {
  it("returns claims for a valid token", async () => {
    const token = await signJwt({ sub: "u1", has_active_subscription: true });
    const result = await verifyAccessToken(token, { keys: [publicJwk] });
    expect(result.sub).toBe("u1");
    expect(result.has_active_subscription).toBe(true);
  });

  it("rejects malformed token", async () => {
    await expect(verifyAccessToken("not.a.token", { keys: [publicJwk] })).rejects.toThrow();
  });

  it("rejects token signed by different key", async () => {
    const { privateKey: otherKey } = await generateKeyPair("RS256");
    const token = await new SignJWT({ sub: "u1" })
      .setProtectedHeader({ alg: "RS256", kid: "wrong-key" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(otherKey);
    await expect(verifyAccessToken(token, { keys: [publicJwk] })).rejects.toThrow();
  });
});
