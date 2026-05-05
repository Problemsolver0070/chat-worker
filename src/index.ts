import { fetchJwks } from "./jwks";
import { verifyAccessToken, type AccessTokenClaims } from "./jwt";
import { fetchUsersMe, type UsersMeResult } from "./users";
import type { WorkerEnv } from "./config";

const COOKIE_NAME = "sb-access-token";

/**
 * Model-invoking API paths that require an active subscription. These
 * are the Open WebUI / LibreChat endpoints that actually call an LLM
 * upstream (chat, completions, embeddings, audio TTS, image gen).
 * UI assets, settings, auth endpoints, and agent-management paths are
 * NOT gated here; they only need a valid JWT.
 *
 * The list is the union of every OWUI 0.4.3 LLM-upstream route family
 * we know about. New families (e.g. STT, batch) need to be added here
 * to keep the billing gate complete.
 */
export const MODEL_API_PATH_PREFIXES: readonly string[] = [
  // Chat completions (multiple aliases across OpenAI / OWUI / LibreChat).
  "/api/chat/completions",
  "/api/v1/chat/completions",
  "/openai/chat/completions",
  "/openai/v1/chat/completions",
  // Non-chat completions (legacy OpenAI shape).
  "/api/v1/completions",
  // Anthropic-shape messages.
  "/api/v1/messages",
  "/api/messages",
  // Ollama-style generation.
  "/ollama/api/chat",
  "/ollama/api/generate",
  // Embeddings.
  "/api/v1/embeddings",
  // Audio synthesis (TTS).
  "/api/v1/audio/speech",
  // Image generation.
  "/api/v1/images/generations",
] as const;

/**
 * Returns true when the request targets a model-completion endpoint
 * (POST only). Exported so the test suite can pin the exact set.
 */
export function isModelApiCall(req: Request): boolean {
  if (req.method !== "POST") return false;
  const url = new URL(req.url);
  return MODEL_API_PATH_PREFIXES.some((prefix) =>
    url.pathname.startsWith(prefix),
  );
}

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
    // (R9 agent prompt editor) using a minted LibreChat JWT. We let
    // non-model /api/* requests flow through untouched. LibreChat itself
    // enforces auth on those routes via the Bearer token; the Worker's
    // role is to gate the chat UI and model-completion paths.
    //
    // Model-completion paths (e.g. /api/chat/completions) are NOT bypassed
    // here; they fall through to the JWT + subscription check below so the
    // worker can enforce the 402 gate for expired users.
    if (url.pathname.startsWith("/api/") && !isModelApiCall(req)) {
      return fetch(req);
    }

    const cookie = parseCookie(req.headers.get("cookie") ?? "", COOKIE_NAME);

    let validatedClaims: AccessTokenClaims | null = null;
    let validatedJwt: string | null = null;
    let reason: string;

    if (!cookie) {
      reason = "no_cookie";
    } else {
      try {
        const jwksUrl = `${env.SUPABASE_URL}/auth/v1/.well-known/jwks.json`;
        const jwks = await fetchJwks(jwksUrl, env.JWKS_CACHE);
        const claims = await verifyAccessToken(cookie, jwks);
        validatedClaims = claims;
        validatedJwt = cookie;
        reason = "allowed";
      } catch (err) {
        reason = `jwt_error: ${(err as Error).message}`;
      }
    }

    // Any valid JWT means the user is signed in. For UI paths that is
    // sufficient; model-completion paths additionally require an active
    // subscription (checked below via the /v1/users/me response).
    const signedIn = validatedClaims !== null;

    // Fetch name + subscription status from the backend (cached) when we
    // have a validated JWT. The result populates x-forwarded-name and
    // x-forwarded-subscription-status on the forwarded request and lets
    // us deny model-completion access for `expired` status. Failure is
    // graceful: we fall back to the existing email-only header set so a
    // backend outage does not break chat for already-paying users.
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
      decision: signedIn ? "allow" : "deny",
      reason,
      path: url.pathname,
      subscription_status: usersMe?.subscription_status ?? null,
    }));

    if (env.WORKER_MODE === "shadow") {
      return fetch(validatedClaims ? withTrustedHeaders(req, validatedClaims, usersMe) : req);
    }

    if (signedIn) {
      // Model-completion paths: gate on active subscription. Users with
      // expired subscriptions can browse the chat UI but cannot invoke
      // any model. Return 402 with a JSON body the client can render.
      if (isModelApiCall(req) && usersMe?.subscription_status === "expired") {
        return new Response(
          JSON.stringify({
            error: {
              type: "subscription_expired",
              message: "Subscribe at thefixer.in/app/billing/upgrade to use models.",
            },
          }),
          { status: 402, headers: { "content-type": "application/json" } },
        );
      }
      return fetch(validatedClaims ? withTrustedHeaders(req, validatedClaims, usersMe) : req);
    }

    // Not signed in (no cookie or invalid JWT): redirect to login.
    if (reason === "no_cookie" || reason.startsWith("jwt_error")) {
      const target = `${env.LOGIN_REDIRECT}?next=${encodeURIComponent(req.url)}`;
      return Response.redirect(target, 302);
    }
    // Fallback: redirect to login (should not normally be reached).
    const target = `${env.LOGIN_REDIRECT}?next=${encodeURIComponent(req.url)}`;
    return Response.redirect(target, 302);
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
