import { fetchJwks } from "./jwks";
import { verifyAccessToken, type AccessTokenClaims } from "./jwt";
import { fetchUsersMe, type UsersMeResult } from "./users";
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

    // Service-to-service bypass for backend admin tooling. The api at
    // api.thefixer.in needs to call LibreChat's /api/agents endpoints
    // (R9 agent prompt editor) using a minted LibreChat JWT. This Worker
    // is currently configured to redirect every cookie-less request to
    // /login, which would convert the Bearer-token traffic into a 302.
    // We let any /api/* request flow through untouched. LibreChat itself
    // enforces auth on those routes via the Bearer token; the Worker's
    // role is to gate the chat UI, not the API.
    if (url.pathname.startsWith("/api/")) {
      return fetch(req);
    }

    const cookie = parseCookie(req.headers.get("cookie") ?? "", COOKIE_NAME);

    let allowed: boolean;
    let reason: string;
    let validatedClaims: AccessTokenClaims | null = null;
    let validatedJwt: string | null = null;

    if (!cookie) {
      allowed = false;
      reason = "no_cookie";
    } else {
      try {
        const jwksUrl = `${env.SUPABASE_URL}/auth/v1/.well-known/jwks.json`;
        const jwks = await fetchJwks(jwksUrl, env.JWKS_CACHE);
        const claims = await verifyAccessToken(cookie, jwks);
        validatedClaims = claims;
        validatedJwt = cookie;
        allowed = Boolean(claims.has_active_subscription);
        reason = allowed ? "allowed" : "no_subscription";
      } catch (err) {
        allowed = false;
        reason = `jwt_error: ${(err as Error).message}`;
      }
    }

    // Fetch name + subscription status from the backend (cached) when we
    // have a validated JWT. The result populates x-forwarded-name and
    // x-forwarded-subscription-status on the forwarded request and lets
    // us deny chat access for `expired` status. Failure is graceful: we
    // fall back to the existing email-only header set so a backend
    // outage does not break chat for already-paying users.
    let usersMe: UsersMeResult | null = null;
    if (validatedClaims && validatedJwt) {
      usersMe = await fetchUsersMe({
        apiBaseUrl: env.API_BASE_URL,
        jwt: validatedJwt,
        userId: validatedClaims.sub,
        cache: env.JWKS_CACHE,
      });
    }

    console.log(JSON.stringify({
      mode: env.WORKER_MODE,
      decision: allowed ? "allow" : "deny",
      reason,
      path: url.pathname,
      subscription_status: usersMe?.subscription_status ?? null,
    }));

    if (env.WORKER_MODE === "shadow") {
      return fetch(validatedClaims ? withTrustedHeaders(req, validatedClaims, usersMe) : req);
    }

    if (allowed) {
      // Backend says the subscription is expired (PayPal sub_status flipped
      // to CANCELLED/SUSPENDED) but the cached JWT claim still says active.
      // Honour the fresher backend signal and redirect to upgrade.
      if (usersMe?.subscription_status === "expired") {
        return Response.redirect(env.UPGRADE_REDIRECT, 302);
      }
      return fetch(validatedClaims ? withTrustedHeaders(req, validatedClaims, usersMe) : req);
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
  headers.delete("X-Forwarded-Name");
  headers.delete("X-Forwarded-Subscription-Status");
  return new Request(orig, { headers });
}

function withTrustedHeaders(
  req: Request,
  claims: AccessTokenClaims,
  usersMe: UsersMeResult | null,
): Request {
  // Caller must pass a request that has already been through stripSpoofedHeaders.
  const headers = new Headers(req.headers);
  if (claims.email) headers.set("X-Forwarded-Email", claims.email);
  if (claims.sub) headers.set("X-Forwarded-User", claims.sub);
  if (usersMe?.name) headers.set("X-Forwarded-Name", usersMe.name);
  if (usersMe?.subscription_status) {
    headers.set("X-Forwarded-Subscription-Status", usersMe.subscription_status);
  }
  return new Request(req, { headers });
}
