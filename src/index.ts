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
  // LibreChat 0.8.5 agents send paths (the live wire today; modelSpecs all
  // resolve to `endpoint: "agents"`, the client POSTs to /api/agents/chat).
  "/api/agents/chat",
  "/api/agents/v1/chat/completions",
  "/api/agents/v1/responses",
  "/api/agents/responses",
  // Chat completions aliases (OpenAI / OWUI / generic LibreChat shapes).
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
  // LibreChat 0.8.5 speech routes (STT + TTS) drive paid model usage too.
  "/api/files/speech/stt",
  "/api/files/speech/tts",
] as const;

/**
 * Regex for the LibreChat 0.8.5 agent tool-call POST path:
 *   POST /api/agents/tools/:toolId/call
 * The tools sub-router is mounted at /tools inside the agents v1 router
 * (api/server/routes/agents/v1.js: router.use('/tools', tools)), and
 * tools.js exposes router.post('/:toolId/call', ...). Full path therefore
 * has only one dynamic segment (toolId), not an agentId.
 * This drives paid model usage and must be gated.
 */
const TOOL_CALL_PATH_REGEX = /^\/api\/agents\/tools\/[^/]+\/call$/;

/**
 * Returns true when the request targets a model-completion endpoint.
 * Methods covered:
 *   POST: most model endpoints (chat, completions, messages, etc.)
 *   GET:  /api/agents/chat/stream/:streamId (SSE resume)
 *   PUT:  /api/messages/:conv/:msg (regenerate-on-edit)
 * Exported so the test suite can pin the exact set.
 */
export function isModelApiCall(req: Request): boolean {
  const url = new URL(req.url);
  const path = url.pathname;
  if (req.method === "POST") {
    if (MODEL_API_PATH_PREFIXES.some((prefix) => path.startsWith(prefix))) {
      return true;
    }
    if (TOOL_CALL_PATH_REGEX.test(path)) {
      return true;
    }
    return false;
  }
  if (req.method === "GET") {
    // SSE resume: the client reconnects to a running stream and the
    // server keeps generating tokens. Same billing impact as the
    // initial POST, so gate it under the same subscription check.
    if (path.startsWith("/api/agents/chat/stream/")) {
      return true;
    }
    return false;
  }
  if (req.method === "PUT") {
    // Regenerate-on-edit: PUT /api/messages/:conv/:msg edits a prior
    // message and triggers a fresh model call. Must be gated.
    if (path.startsWith("/api/messages/")) {
      return true;
    }
    return false;
  }
  return false;
}

/**
 * Returns a new Request that is a clone of `req` with the
 * `X-Edge-Secret` header set to the configured value. Used for every
 * upstream forward (gated and bypass) so the LibreChat origin can
 * cryptographically verify the request came from the Worker rather
 * than from a public client hitting the VM directly.
 */
function withEdgeSecret(req: Request, env: WorkerEnv): Request {
  const headers = new Headers(req.headers);
  if (env.EDGE_SECRET) {
    headers.set("X-Edge-Secret", env.EDGE_SECRET);
  }
  return new Request(req, { headers });
}

function jsonError(
  status: number,
  error: {
    type: string;
    title: string;
    message: string;
    action?: string;
    upgrade_url?: string;
    retry_after_seconds?: number;
  },
  headers?: Record<string, string>,
): Response {
  return new Response(
    JSON.stringify({ error }),
    {
      status,
      headers: {
        "content-type": "application/json",
        ...headers,
      },
    },
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
    //
    // /api/agents/chat/abort is intentionally NOT gated (UX: an expired
    // user mid-stream should still be able to cancel; abort does not
    // drive paid model usage).
    if (url.pathname.startsWith("/api/") && !isModelApiCall(req)) {
      return fetch(withEdgeSecret(req, env));
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
      const fwd = validatedClaims ? withTrustedHeaders(req, validatedClaims, usersMe) : req;
      return fetch(withEdgeSecret(fwd, env));
    }

    if (signedIn) {
      // Friction-killer wave (2026-05-07): the worker no longer 402s
      // non-subscribed users on the model path. Every signed-in user is
      // forwarded to LibreChat, where freeMessageCap.js enforces the
      // 3-free-messages cap by counting messages live in chat-mongodb.
      // The worker still validates the JWT (anonymous traffic is still
      // 401-redirected to login below) and still forwards
      // X-Forwarded-Subscription-Status so LibreChat can short-circuit
      // the cap check for active subscribers. See
      // llmfixer-api/docs/superpowers/specs/2026-05-07-friction-killer-wave.md.
      //
      // Fail-CLOSED on backend outage for model-completion paths only.
      // If usersMe is null (cache miss + backend 5xx / network error) we
      // cannot verify the subscription state, so we must not let paid
      // model traffic through. Without this check, a determined attacker
      // could DDoS /v1/users/me to stretch a stale-cancellation window
      // indefinitely. UI paths keep fail-OPEN behavior so signed-in
      // users do not lose chat browsing during a transient outage.
      // Security fix F12 from Wave 2 audit.
      if (isModelApiCall(req) && usersMe === null) {
        return jsonError(503, {
          type: "backend_unavailable",
          title: "Chat temporarily unavailable",
          message: "We could not verify your subscription state, so model calls are paused for safety.",
          action: "Try again in a moment. If this keeps happening, open Support from the dashboard.",
        });
      }
      // F41: edge rate limit on model-API paths only. Keyed by JWT sub so
      // each signed-in account gets its own counter. UI page loads, agent
      // management, and other non-model /api/* paths are NOT rate limited
      // (they cost us nothing). 60 req/60s is generous for normal chat
      // usage but cuts off automated abuse. The binding is optional in
      // the type so older test setups without it still work; in
      // production wrangler.toml provisions RATE_LIMITER on every deploy.
      if (
        isModelApiCall(req) &&
        env.RATE_LIMITER &&
        validatedClaims?.sub
      ) {
        const result = await env.RATE_LIMITER.limit({ key: validatedClaims.sub });
        if (!result.success) {
          return jsonError(
            429,
            {
              type: "rate_limited",
              title: "Too many chat requests",
              message: "You have sent too many model requests in a short time.",
              action: "Wait a minute, then try again.",
              retry_after_seconds: 60,
            },
            { "Retry-After": "60" },
          );
        }
      }
      const fwd = validatedClaims ? withTrustedHeaders(req, validatedClaims, usersMe) : req;
      return fetch(withEdgeSecret(fwd, env));
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
  // Also strip any client-supplied X-Edge-Secret so the Worker is the
  // sole authority on injecting it. A public client cannot forge the
  // secret value (it is unknown to them) but stripping is defence in
  // depth in case the value ever leaks.
  headers.delete("X-Edge-Secret");
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
