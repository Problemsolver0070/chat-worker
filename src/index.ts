import { fetchJwks } from "./jwks";
import { verifyAccessToken } from "./jwt";
import type { WorkerEnv } from "./config";

const COOKIE_NAME = "sb-access-token";

export default {
  async fetch(req: Request, env: WorkerEnv, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);
    const cookie = parseCookie(req.headers.get("cookie") ?? "", COOKIE_NAME);

    let allowed: boolean;
    let reason: string;

    if (!cookie) {
      allowed = false;
      reason = "no_cookie";
    } else {
      try {
        const jwksUrl = `${env.SUPABASE_URL}/auth/v1/.well-known/jwks.json`;
        const jwks = await fetchJwks(jwksUrl, env.JWKS_CACHE);
        const claims = await verifyAccessToken(cookie, jwks);
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
      return fetch(req);
    }

    if (allowed) {
      return fetch(req);
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
