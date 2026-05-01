import { fetchJwks } from "./jwks";
import { verifyAccessToken, type AccessTokenClaims } from "./jwt";
import type { WorkerEnv } from "./config";

const COOKIE_NAME = "sb-access-token";

export default {
  async fetch(originalReq: Request, env: WorkerEnv, ctx: ExecutionContext): Promise<Response> {
    // Strip client-supplied trusted-header values BEFORE any other logic so
    // they can never reach origin. Origin (Open WebUI) is configured with
    // WEBUI_AUTH_TRUSTED_EMAIL_HEADER, so any spoofed X-Forwarded-Email or
    // X-Forwarded-User from a public client would otherwise authenticate the
    // attacker as that user. Re-set only after JWT validates.
    const req = stripSpoofedHeaders(originalReq);
    const url = new URL(req.url);
    const cookie = parseCookie(req.headers.get("cookie") ?? "", COOKIE_NAME);

    let allowed: boolean;
    let reason: string;
    let validatedClaims: AccessTokenClaims | null = null;

    if (!cookie) {
      allowed = false;
      reason = "no_cookie";
    } else {
      try {
        const jwksUrl = `${env.SUPABASE_URL}/auth/v1/.well-known/jwks.json`;
        const jwks = await fetchJwks(jwksUrl, env.JWKS_CACHE);
        const claims = await verifyAccessToken(cookie, jwks);
        validatedClaims = claims;
        allowed = Boolean(claims.has_active_subscription);
        reason = allowed ? "allowed" : "no_subscription";
      } catch (err) {
        allowed = false;
        reason = `jwt_error: ${(err as Error).message}`;
      }
    }

    console.log(JSON.stringify({
      mode: env.WORKER_MODE,
      decision: allowed ? "allow" : "deny",
      reason,
      path: url.pathname,
    }));

    if (env.WORKER_MODE === "shadow") {
      return fetch(validatedClaims ? withTrustedHeaders(req, validatedClaims) : req);
    }

    if (allowed) {
      return fetch(validatedClaims ? withTrustedHeaders(req, validatedClaims) : req);
    }

    if (reason === "no_cookie" || reason.startsWith("jwt_error")) {
      const target = `${env.LOGIN_REDIRECT}?next=${encodeURIComponent(req.url)}`;
      return Response.redirect(target, 302);
    }
    return Response.redirect(env.UPGRADE_REDIRECT, 302);
  },
};

function parseCookie(header: string, name: string): string | null {
  const parts = header.split(";").map((s) => s.trim());
  for (const p of parts) {
    const idx = p.indexOf("=");
    if (idx === -1) continue;
    if (p.slice(0, idx) === name) return p.slice(idx + 1);
  }
  return null;
}

function stripSpoofedHeaders(orig: Request): Request {
  const headers = new Headers(orig.headers);
  // Headers#delete is case-insensitive per the Fetch spec, so this catches
  // any case variant a client might try (x-forwarded-email, X-FORWARDED-USER, etc.)
  headers.delete("X-Forwarded-Email");
  headers.delete("X-Forwarded-User");
  return new Request(orig, { headers });
}

function withTrustedHeaders(req: Request, claims: AccessTokenClaims): Request {
  // Caller must pass a request that has already been through stripSpoofedHeaders.
  const headers = new Headers(req.headers);
  if (claims.email) headers.set("X-Forwarded-Email", claims.email);
  if (claims.sub) headers.set("X-Forwarded-User", claims.sub);
  return new Request(req, { headers });
}
