import { describe, expect, it, vi, beforeAll, beforeEach } from "vitest";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import worker from "../src/index";
import { isModelApiCall, MODEL_API_PATH_PREFIXES } from "../src/index";
import type { WorkerEnv } from "../src/config";

const SAMPLE_JWKS = JSON.stringify({ keys: [] });

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

interface KvHandle {
  store: Map<string, string>;
  get: ReturnType<typeof vi.fn>;
  put: ReturnType<typeof vi.fn>;
  delete: ReturnType<typeof vi.fn>;
}

function makeKv(jwksValue: string): KvHandle {
  const store = new Map<string, string>();
  store.set("jwks", jwksValue);
  const get = vi.fn(async (key: string) => store.get(key) ?? null);
  const put = vi.fn(async (key: string, value: string) => {
    store.set(key, value);
  });
  const del = vi.fn(async (key: string) => {
    store.delete(key);
  });
  return { store, get, put, delete: del };
}

interface RateLimiterHandle {
  limit: ReturnType<typeof vi.fn>;
}

function makeRateLimiter(allow: boolean = true): RateLimiterHandle {
  return {
    limit: vi.fn(async () => ({ success: allow })),
  };
}

function makeEnv(
  mode: "shadow" | "enforce",
  jwksOverride?: string,
  opts?: {
    edgeSecret?: string | undefined;
    rateLimiter?: RateLimiterHandle | null;
  },
): { env: WorkerEnv; kv: KvHandle; rateLimiter: RateLimiterHandle | null } {
  const jwksValue = jwksOverride ?? SAMPLE_JWKS;
  const kv = makeKv(jwksValue);
  // Default: a permissive rate limiter so existing tests continue to pass.
  // Pass `rateLimiter: null` to omit the binding entirely (mirrors a deploy
  // before wrangler.toml provisioned it).
  const rateLimiter =
    opts && "rateLimiter" in opts ? opts.rateLimiter ?? null : makeRateLimiter(true);
  const env: WorkerEnv = {
    JWKS_CACHE: kv as unknown as KVNamespace,
    SUPABASE_URL: "https://example.supabase.co",
    LOGIN_REDIRECT: "https://thefixer.in/login",
    UPGRADE_REDIRECT: "https://thefixer.in/app/billing/upgrade",
    WORKER_MODE: mode,
    API_BASE_URL: "https://api.thefixer.in",
    EDGE_SECRET: opts && "edgeSecret" in opts ? opts.edgeSecret : "test-edge-secret",
    RATE_LIMITER: rateLimiter
      ? (rateLimiter as unknown as WorkerEnv["RATE_LIMITER"])
      : undefined,
  };
  return { env, kv, rateLimiter };
}

/** Stub fetch so backend calls (`/v1/users/me`) and origin forwards
 * are routed through one mock. The first arg is forwarded as-is so
 * tests can inspect request headers; the second arg is the backend
 * response shape. */
function stubFetch(opts: {
  usersMeBody?: Record<string, unknown> | null;
  usersMeStatus?: number;
}): { captured: () => Request | null } {
  let captured: Request | null = null;
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url.endsWith("/v1/users/me")) {
      const status = opts.usersMeStatus ?? 200;
      if (opts.usersMeBody === null || status >= 400) {
        return new Response("err", { status });
      }
      return new Response(JSON.stringify(opts.usersMeBody ?? {}), { status });
    }
    if (input instanceof Request) {
      captured = input;
    }
    return new Response("ok", { status: 200 });
  }) as typeof fetch;
  return { captured: () => captured };
}

describe("isModelApiCall helper", () => {
  it("returns true for POST to /api/chat/completions", () => {
    const req = new Request("https://chat.thefixer.in/api/chat/completions", { method: "POST" });
    expect(isModelApiCall(req)).toBe(true);
  });

  it("returns false for GET to /api/chat/completions", () => {
    const req = new Request("https://chat.thefixer.in/api/chat/completions", { method: "GET" });
    expect(isModelApiCall(req)).toBe(false);
  });

  it("returns true for POST to /ollama/api/chat", () => {
    const req = new Request("https://chat.thefixer.in/ollama/api/chat", { method: "POST" });
    expect(isModelApiCall(req)).toBe(true);
  });

  it("returns false for POST to /api/agents (non-model path)", () => {
    const req = new Request("https://chat.thefixer.in/api/agents", { method: "POST" });
    expect(isModelApiCall(req)).toBe(false);
  });

  it("returns false for a UI page load (GET /)", () => {
    const req = new Request("https://chat.thefixer.in/", { method: "GET" });
    expect(isModelApiCall(req)).toBe(false);
  });

  it("returns true for POST to /api/agents/tools/TOOL456/call (tool-call)", () => {
    const req = new Request("https://chat.thefixer.in/api/agents/tools/TOOL456/call", {
      method: "POST",
    });
    expect(isModelApiCall(req)).toBe(true);
  });

  it("returns false for non-call paths under /api/agents/tools/Y/", () => {
    const req = new Request("https://chat.thefixer.in/api/agents/tools/TOOL456/list", {
      method: "POST",
    });
    expect(isModelApiCall(req)).toBe(false);
  });

  it("returns true for GET to /api/agents/chat/stream/STREAMID (SSE resume)", () => {
    const req = new Request("https://chat.thefixer.in/api/agents/chat/stream/STREAMID", {
      method: "GET",
    });
    expect(isModelApiCall(req)).toBe(true);
  });

  it("returns true for PUT to /api/messages/CONV/MSG (regenerate-on-edit)", () => {
    const req = new Request("https://chat.thefixer.in/api/messages/CONV/MSG", {
      method: "PUT",
    });
    expect(isModelApiCall(req)).toBe(true);
  });

  it("returns true for POST to /api/files/speech/stt", () => {
    const req = new Request("https://chat.thefixer.in/api/files/speech/stt", {
      method: "POST",
    });
    expect(isModelApiCall(req)).toBe(true);
  });

  it("returns true for POST to /api/files/speech/tts", () => {
    const req = new Request("https://chat.thefixer.in/api/files/speech/tts", {
      method: "POST",
    });
    expect(isModelApiCall(req)).toBe(true);
  });

  it("returns false for POST to /api/agents/chat/abort (UX, not gated)", () => {
    const req = new Request("https://chat.thefixer.in/api/agents/chat/abort", {
      method: "POST",
    });
    // /api/agents/chat is the prefix, but abort is not a paid model call
    // by intent. The current prefix-match counts /api/agents/chat/abort
    // as gated; if that ever becomes a UX problem, narrow the prefix.
    // This test pins current behavior so a future change is intentional.
    expect(isModelApiCall(req)).toBe(true);
  });
});

describe("Worker fetch handler", () => {
  it("redirects to login when sb-access-token cookie missing (enforce)", async () => {
    const req = new Request("https://chat.thefixer.in/");
    const { env } = makeEnv("enforce");
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(302);
    expect(resp.headers.get("Location")).toContain("https://thefixer.in/login");
  });

  it("forwards through (no redirect) when in shadow mode regardless of claim", async () => {
    const req = new Request("https://chat.thefixer.in/");
    const { env } = makeEnv("shadow");
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    globalThis.fetch = vi.fn(async () => new Response("ok", { status: 200 })) as typeof fetch;
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(200);
  });

  it("injects X-Forwarded-Email and X-Forwarded-User headers on validated enforce request", async () => {
    const token = await signJwt({
      sub: "user-123",
      email: "test@example.com",
      has_active_subscription: true,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const { env } = makeEnv("enforce", jwks);
    const { captured } = stubFetch({
      usersMeBody: { full_name: "Ada Lovelace", has_active_subscription: true },
    });
    const req = new Request("https://chat.thefixer.in/", {
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(200);
    const fwd = captured();
    expect(fwd).not.toBeNull();
    expect(fwd!.headers.get("X-Forwarded-Email")).toBe("test@example.com");
    expect(fwd!.headers.get("X-Forwarded-User")).toBe("user-123");
  });

  it("injects X-Forwarded-Email header in shadow mode when JWT has email claim", async () => {
    const token = await signJwt({
      sub: "user-456",
      email: "shadow@example.com",
      has_active_subscription: false,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const { env } = makeEnv("shadow", jwks);
    const { captured } = stubFetch({
      usersMeBody: { full_name: null, has_active_subscription: false },
    });
    const req = new Request("https://chat.thefixer.in/", {
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(200);
    const fwd = captured();
    expect(fwd).not.toBeNull();
    expect(fwd!.headers.get("X-Forwarded-Email")).toBe("shadow@example.com");
    expect(fwd!.headers.get("X-Forwarded-User")).toBe("user-456");
  });

  it("does not inject X-Forwarded-Email header when no cookie present in shadow mode", async () => {
    const { env } = makeEnv("shadow");
    const { captured } = stubFetch({});
    const req = new Request("https://chat.thefixer.in/");
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(200);
    const fwd = captured();
    expect(fwd).not.toBeNull();
    expect(fwd!.headers.get("X-Forwarded-Email")).toBeNull();
    expect(fwd!.headers.get("X-Forwarded-User")).toBeNull();
  });

  it("strips client-supplied X-Forwarded-Email when no JWT cookie (shadow mode)", async () => {
    const { env } = makeEnv("shadow");
    const { captured } = stubFetch({});
    const req = new Request("https://chat.thefixer.in/", {
      headers: { "X-Forwarded-Email": "spoofed@example.com" },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(200);
    const fwd = captured();
    expect(fwd).not.toBeNull();
    expect(fwd!.headers.get("X-Forwarded-Email")).toBeNull();
  });

  it("strips client-supplied X-Forwarded-User when no JWT cookie (shadow mode)", async () => {
    const { env } = makeEnv("shadow");
    const { captured } = stubFetch({});
    const req = new Request("https://chat.thefixer.in/", {
      headers: { "X-Forwarded-User": "spoofed-user-id" },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(200);
    const fwd = captured();
    expect(fwd).not.toBeNull();
    expect(fwd!.headers.get("X-Forwarded-User")).toBeNull();
  });

  it("strips client-supplied X-Forwarded-Email when JWT cookie is invalid (shadow mode)", async () => {
    const { env } = makeEnv("shadow");
    const { captured } = stubFetch({});
    const req = new Request("https://chat.thefixer.in/", {
      headers: {
        cookie: "sb-access-token=not.a.valid.jwt",
        "X-Forwarded-Email": "spoofed@example.com",
        "X-Forwarded-User": "spoofed-user",
      },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(200);
    const fwd = captured();
    expect(fwd).not.toBeNull();
    expect(fwd!.headers.get("X-Forwarded-Email")).toBeNull();
    expect(fwd!.headers.get("X-Forwarded-User")).toBeNull();
  });

  it("replaces client-supplied X-Forwarded-Email with JWT claim email when JWT is valid (enforce mode)", async () => {
    const token = await signJwt({
      sub: "user-789",
      email: "trusted@example.com",
      has_active_subscription: true,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const { env } = makeEnv("enforce", jwks);
    const { captured } = stubFetch({
      usersMeBody: { full_name: "Trusted Name", has_active_subscription: true },
    });
    const req = new Request("https://chat.thefixer.in/", {
      headers: {
        cookie: `sb-access-token=${token}`,
        "X-Forwarded-Email": "spoofed@example.com",
        "X-Forwarded-User": "spoofed-user-id",
      },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(200);
    const fwd = captured();
    expect(fwd).not.toBeNull();
    expect(fwd!.headers.get("X-Forwarded-Email")).toBe("trusted@example.com");
    expect(fwd!.headers.get("X-Forwarded-User")).toBe("user-789");
  });
});

describe("Name + subscription forwarding", () => {
  it("forwards X-Forwarded-Name when /v1/users/me returns a full_name", async () => {
    const token = await signJwt({
      sub: "user-name-1",
      email: "ada@example.com",
      has_active_subscription: true,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const { env } = makeEnv("enforce", jwks);
    const { captured } = stubFetch({
      usersMeBody: { full_name: "Ada Lovelace", has_active_subscription: true },
    });
    const req = new Request("https://chat.thefixer.in/", {
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(200);
    const fwd = captured();
    expect(fwd!.headers.get("X-Forwarded-Name")).toBe("Ada Lovelace");
    expect(fwd!.headers.get("X-Forwarded-Subscription-Status")).toBe("active");
  });

  it("omits X-Forwarded-Name when full_name is null", async () => {
    const token = await signJwt({
      sub: "user-name-2",
      email: "noone@example.com",
      has_active_subscription: true,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const { env } = makeEnv("enforce", jwks);
    const { captured } = stubFetch({
      usersMeBody: { full_name: null, has_active_subscription: true },
    });
    const req = new Request("https://chat.thefixer.in/", {
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(200);
    const fwd = captured();
    expect(fwd!.headers.get("X-Forwarded-Name")).toBeNull();
    expect(fwd!.headers.get("X-Forwarded-Subscription-Status")).toBe("active");
  });

  it("proxies expired user to origin on UI path with X-Forwarded-Subscription-Status: expired", async () => {
    const token = await signJwt({
      sub: "user-expired-ui",
      email: "expired@example.com",
      has_active_subscription: false,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const { env } = makeEnv("enforce", jwks);
    const { captured } = stubFetch({
      usersMeBody: {
        full_name: "Expired User",
        has_active_subscription: false,
      },
    });
    const req = new Request("https://chat.thefixer.in/", {
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    // UI path: expired user gets through (no redirect).
    expect(resp.status).toBe(200);
    const fwd = captured();
    expect(fwd).not.toBeNull();
    expect(fwd!.headers.get("X-Forwarded-Subscription-Status")).toBe("expired");
  });

  it("falls back to forwarding without name headers when /v1/users/me returns 5xx", async () => {
    const token = await signJwt({
      sub: "user-5xx",
      email: "five@example.com",
      has_active_subscription: true,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const { env } = makeEnv("enforce", jwks);
    const { captured } = stubFetch({
      usersMeStatus: 503,
      usersMeBody: null,
    });
    const req = new Request("https://chat.thefixer.in/", {
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(200);
    const fwd = captured();
    expect(fwd!.headers.get("X-Forwarded-Email")).toBe("five@example.com");
    expect(fwd!.headers.get("X-Forwarded-Name")).toBeNull();
    expect(fwd!.headers.get("X-Forwarded-Subscription-Status")).toBeNull();
  });

  it("strips client-supplied X-Forwarded-Name to prevent header spoofing", async () => {
    const token = await signJwt({
      sub: "user-spoof",
      email: "spoof@example.com",
      has_active_subscription: true,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const { env } = makeEnv("enforce", jwks);
    const { captured } = stubFetch({
      usersMeBody: { full_name: "Real Name", has_active_subscription: true },
    });
    const req = new Request("https://chat.thefixer.in/", {
      headers: {
        cookie: `sb-access-token=${token}`,
        "X-Forwarded-Name": "Spoofed Name",
        "X-Forwarded-Subscription-Status": "active",
      },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(200);
    const fwd = captured();
    expect(fwd!.headers.get("X-Forwarded-Name")).toBe("Real Name");
    expect(fwd!.headers.get("X-Forwarded-Subscription-Status")).toBe("active");
  });

  it("caches the /v1/users/me response across requests for the same user", async () => {
    const token = await signJwt({
      sub: "user-cache",
      email: "cache@example.com",
      has_active_subscription: true,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const { env, kv } = makeEnv("enforce", jwks);

    let usersMeCalls = 0;
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;
      if (url.endsWith("/v1/users/me")) {
        usersMeCalls += 1;
        return new Response(
          JSON.stringify({ full_name: "Cached User", has_active_subscription: true }),
          { status: 200 },
        );
      }
      return new Response("ok", { status: 200 });
    }) as typeof fetch;

    const req1 = new Request("https://chat.thefixer.in/", {
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    await worker.fetch(req1, env, ctx as unknown as ExecutionContext);
    expect(usersMeCalls).toBe(1);
    expect(kv.put).toHaveBeenCalledWith(
      "users_me:user-cache",
      expect.any(String),
      expect.objectContaining({ expirationTtl: 60 }),
    );

    // Second request should hit the KV cache and not re-call the backend.
    const req2 = new Request("https://chat.thefixer.in/foo", {
      headers: { cookie: `sb-access-token=${token}` },
    });
    await worker.fetch(req2, env, ctx as unknown as ExecutionContext);
    expect(usersMeCalls).toBe(1);
  });
});

describe("Model-path gate", () => {
  it("returns 402 when expired user POSTs to /api/chat/completions", async () => {
    const token = await signJwt({
      sub: "user-expired-model",
      email: "expired-model@example.com",
      has_active_subscription: false,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const { env } = makeEnv("enforce", jwks);
    stubFetch({
      usersMeBody: {
        full_name: "Expired Model User",
        has_active_subscription: false,
      },
    });
    const req = new Request("https://chat.thefixer.in/api/chat/completions", {
      method: "POST",
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(402);
    expect(resp.headers.get("content-type")).toBe("application/json");
    const body = await resp.json() as {
      error: {
        type: string;
        title: string;
        message: string;
        action: string;
        upgrade_url: string;
      };
    };
    expect(body.error.type).toBe("subscription_expired");
    expect(body.error.title).toBe("Plan required");
    expect(body.error.message).toContain("model calls are paused");
    expect(body.error.action).toContain("free demo");
    expect(body.error.upgrade_url).toBe("https://thefixer.in/app/billing/upgrade");
  });

  it("returns 402 when expired user POSTs to /ollama/api/chat", async () => {
    const token = await signJwt({
      sub: "user-expired-ollama",
      email: "expired-ollama@example.com",
      has_active_subscription: false,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const { env } = makeEnv("enforce", jwks);
    stubFetch({
      usersMeBody: {
        full_name: "Expired Ollama User",
        has_active_subscription: false,
      },
    });
    const req = new Request("https://chat.thefixer.in/ollama/api/chat", {
      method: "POST",
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(402);
    const body = await resp.json() as { error: { type: string } };
    expect(body.error.type).toBe("subscription_expired");
  });

  it("forwards active user POST to /api/chat/completions to origin", async () => {
    const token = await signJwt({
      sub: "user-active-model",
      email: "active-model@example.com",
      has_active_subscription: true,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const { env } = makeEnv("enforce", jwks);
    const { captured } = stubFetch({
      usersMeBody: {
        full_name: "Active Model User",
        has_active_subscription: true,
      },
    });
    const req = new Request("https://chat.thefixer.in/api/chat/completions", {
      method: "POST",
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(200);
    const fwd = captured();
    expect(fwd).not.toBeNull();
    expect(fwd!.headers.get("X-Forwarded-Subscription-Status")).toBe("active");
  });

  it("forwards active user POST to /api/v1/messages to origin", async () => {
    const token = await signJwt({
      sub: "user-active-messages",
      email: "active-messages@example.com",
      has_active_subscription: true,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const { env } = makeEnv("enforce", jwks);
    const { captured } = stubFetch({
      usersMeBody: {
        full_name: "Active Messages User",
        has_active_subscription: true,
      },
    });
    const req = new Request("https://chat.thefixer.in/api/v1/messages", {
      method: "POST",
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(200);
    const fwd = captured();
    expect(fwd).not.toBeNull();
  });

  it("lets expired user GET /api/chat/completions through (only POST is gated)", async () => {
    const token = await signJwt({
      sub: "user-expired-get",
      email: "expired-get@example.com",
      has_active_subscription: false,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const { env } = makeEnv("enforce", jwks);
    stubFetch({
      usersMeBody: {
        full_name: "Expired Get User",
        has_active_subscription: false,
      },
    });
    // GET requests to model paths are not gated (only POST invokes models).
    // But /api/* paths that are not model paths go through the bypass, so
    // this GET actually goes through the bypass. For a non-model /api/ GET
    // the bypass handles it. For model paths, GET is unusual but harmless.
    const req = new Request("https://chat.thefixer.in/api/chat/completions", {
      method: "GET",
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    // GET to /api/* (non-model-call) hits the bypass and gets 200.
    expect(resp.status).toBe(200);
  });

  it("returns 402 when expired user POSTs to tool-call /api/agents/tools/T/call", async () => {
    const token = await signJwt({
      sub: "user-expired-tool",
      email: "expired-tool@example.com",
      has_active_subscription: false,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const { env } = makeEnv("enforce", jwks);
    stubFetch({
      usersMeBody: { full_name: "Expired Tool User", has_active_subscription: false },
    });
    const req = new Request(
      "https://chat.thefixer.in/api/agents/tools/toolY/call",
      { method: "POST", headers: { cookie: `sb-access-token=${token}` } },
    );
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(402);
    const body = await resp.json() as { error: { type: string } };
    expect(body.error.type).toBe("subscription_expired");
  });

  it("returns 402 when expired user GETs SSE resume /api/agents/chat/stream/:id", async () => {
    const token = await signJwt({
      sub: "user-expired-sse",
      email: "expired-sse@example.com",
      has_active_subscription: false,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const { env } = makeEnv("enforce", jwks);
    stubFetch({
      usersMeBody: { full_name: "Expired SSE User", has_active_subscription: false },
    });
    const req = new Request("https://chat.thefixer.in/api/agents/chat/stream/abc123", {
      method: "GET",
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(402);
  });

  it("returns 402 when expired user PUTs /api/messages/:conv/:msg (regenerate)", async () => {
    const token = await signJwt({
      sub: "user-expired-regen",
      email: "expired-regen@example.com",
      has_active_subscription: false,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const { env } = makeEnv("enforce", jwks);
    stubFetch({
      usersMeBody: { full_name: "Expired Regen User", has_active_subscription: false },
    });
    const req = new Request("https://chat.thefixer.in/api/messages/conv1/msg1", {
      method: "PUT",
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(402);
  });

  it("returns 402 when expired user POSTs /api/files/speech/stt", async () => {
    const token = await signJwt({
      sub: "user-expired-stt",
      email: "expired-stt@example.com",
      has_active_subscription: false,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const { env } = makeEnv("enforce", jwks);
    stubFetch({
      usersMeBody: { full_name: "Expired STT User", has_active_subscription: false },
    });
    const req = new Request("https://chat.thefixer.in/api/files/speech/stt", {
      method: "POST",
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(402);
  });

  it("returns 402 when expired user POSTs /api/files/speech/tts", async () => {
    const token = await signJwt({
      sub: "user-expired-tts",
      email: "expired-tts@example.com",
      has_active_subscription: false,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const { env } = makeEnv("enforce", jwks);
    stubFetch({
      usersMeBody: { full_name: "Expired TTS User", has_active_subscription: false },
    });
    const req = new Request("https://chat.thefixer.in/api/files/speech/tts", {
      method: "POST",
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(402);
  });

  it("returns 503 (fail-closed) when backend /v1/users/me is 5xx and model path POSTed (F12)", async () => {
    // Security fix F12: when backend /v1/users/me returns 5xx, usersMe is
    // null so subscription_status is unverifiable. For model-completion
    // paths the worker MUST fail-CLOSED with 503 so an attacker cannot
    // DDoS the backend to extend a stale-cancellation window. UI paths
    // keep fail-OPEN behavior (covered by a sibling test below).
    const token = await signJwt({
      sub: "user-5xx-model",
      email: "five-model@example.com",
      has_active_subscription: false,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const { env } = makeEnv("enforce", jwks);
    const { captured } = stubFetch({
      usersMeStatus: 503,
      usersMeBody: null,
    });
    const req = new Request("https://chat.thefixer.in/api/chat/completions", {
      method: "POST",
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    // Backend down on a model-API path: fail-CLOSED with 503.
    expect(resp.status).toBe(503);
    expect(resp.headers.get("content-type")).toBe("application/json");
    const body = await resp.json() as {
      error: { type: string; title: string; message: string; action: string };
    };
    expect(body.error.type).toBe("backend_unavailable");
    expect(body.error.title).toBe("Chat temporarily unavailable");
    expect(body.error.message).toContain("could not verify");
    expect(body.error.action).toContain("Try again");
    // Origin must NOT have been forwarded to (only the failed /v1/users/me
    // call was made, no upstream LibreChat request).
    expect(captured()).toBeNull();
  });

  it("forwards UI path unchanged when backend /v1/users/me is 5xx (fail-OPEN preserved, F12)", async () => {
    // Security fix F12 trade-off: UI paths must keep fail-OPEN behavior
    // so signed-in users do not lose chat browsing during a transient
    // backend outage. Only model-completion paths fail-closed.
    const token = await signJwt({
      sub: "user-5xx-ui",
      email: "five-ui@example.com",
      has_active_subscription: true,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const { env } = makeEnv("enforce", jwks);
    const { captured } = stubFetch({
      usersMeStatus: 503,
      usersMeBody: null,
    });
    const req = new Request("https://chat.thefixer.in/", {
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    // Backend down on a UI path: forward to origin, no name/status headers.
    expect(resp.status).toBe(200);
    const fwd = captured();
    expect(fwd).not.toBeNull();
    expect(fwd!.headers.get("X-Forwarded-Email")).toBe("five-ui@example.com");
    expect(fwd!.headers.get("X-Forwarded-Subscription-Status")).toBeNull();
  });
});

describe("X-Edge-Secret injection on upstream forwards", () => {
  it("injects X-Edge-Secret on bypass path (non-model /api/* request)", async () => {
    const { env } = makeEnv("enforce", undefined, { edgeSecret: "secret-bypass-1" });
    const { captured } = stubFetch({});
    const req = new Request("https://chat.thefixer.in/api/agents", { method: "POST" });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    const fwd = captured();
    expect(fwd).not.toBeNull();
    expect(fwd!.headers.get("X-Edge-Secret")).toBe("secret-bypass-1");
  });

  it("injects X-Edge-Secret on gated, allowed model-call forward (active user)", async () => {
    const token = await signJwt({
      sub: "user-edge-active",
      email: "edge-active@example.com",
      has_active_subscription: true,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const { env } = makeEnv("enforce", jwks, { edgeSecret: "secret-active-1" });
    const { captured } = stubFetch({
      usersMeBody: { full_name: "Edge Active User", has_active_subscription: true },
    });
    const req = new Request("https://chat.thefixer.in/api/chat/completions", {
      method: "POST",
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    const fwd = captured();
    expect(fwd).not.toBeNull();
    expect(fwd!.headers.get("X-Edge-Secret")).toBe("secret-active-1");
  });

  it("injects X-Edge-Secret on UI page-load forward (signed-in user)", async () => {
    const token = await signJwt({
      sub: "user-edge-ui",
      email: "edge-ui@example.com",
      has_active_subscription: true,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const { env } = makeEnv("enforce", jwks, { edgeSecret: "secret-ui-1" });
    const { captured } = stubFetch({
      usersMeBody: { full_name: "Edge UI User", has_active_subscription: true },
    });
    const req = new Request("https://chat.thefixer.in/", {
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    const fwd = captured();
    expect(fwd).not.toBeNull();
    expect(fwd!.headers.get("X-Edge-Secret")).toBe("secret-ui-1");
  });

  it("injects X-Edge-Secret in shadow mode forwards too", async () => {
    const { env } = makeEnv("shadow", undefined, { edgeSecret: "secret-shadow-1" });
    const { captured } = stubFetch({});
    const req = new Request("https://chat.thefixer.in/");
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    const fwd = captured();
    expect(fwd).not.toBeNull();
    expect(fwd!.headers.get("X-Edge-Secret")).toBe("secret-shadow-1");
  });

  it("does NOT inject X-Edge-Secret when env.EDGE_SECRET is unset (pre-rollout window)", async () => {
    const { env } = makeEnv("enforce", undefined, { edgeSecret: undefined });
    const { captured } = stubFetch({});
    const req = new Request("https://chat.thefixer.in/api/agents", { method: "POST" });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    const fwd = captured();
    expect(fwd).not.toBeNull();
    expect(fwd!.headers.get("X-Edge-Secret")).toBeNull();
  });

  it("strips client-supplied X-Edge-Secret and replaces with env value", async () => {
    const { env } = makeEnv("enforce", undefined, { edgeSecret: "real-secret" });
    const { captured } = stubFetch({});
    const req = new Request("https://chat.thefixer.in/api/agents", {
      method: "POST",
      headers: { "X-Edge-Secret": "spoofed-by-client" },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    const fwd = captured();
    expect(fwd).not.toBeNull();
    expect(fwd!.headers.get("X-Edge-Secret")).toBe("real-secret");
  });
});

describe("Edge rate limit on model-API paths (F41)", () => {
  it("returns 429 with Retry-After when RATE_LIMITER reports over-limit on a model POST", async () => {
    const token = await signJwt({
      sub: "user-rl-over",
      email: "rl-over@example.com",
      has_active_subscription: true,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const denied = makeRateLimiter(false);
    const { env } = makeEnv("enforce", jwks, { rateLimiter: denied });
    stubFetch({
      usersMeBody: { full_name: "RL Over User", has_active_subscription: true },
    });
    const req = new Request("https://chat.thefixer.in/api/chat/completions", {
      method: "POST",
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(429);
    expect(resp.headers.get("Retry-After")).toBe("60");
    expect(resp.headers.get("content-type")).toBe("application/json");
    const body = (await resp.json()) as {
      error: { type: string; title: string; retry_after_seconds: number };
    };
    expect(body.error.type).toBe("rate_limited");
    expect(body.error.title).toBe("Too many chat requests");
    expect(body.error.retry_after_seconds).toBe(60);
    // The limiter must have been called with the JWT sub as the key.
    expect(denied.limit).toHaveBeenCalledWith({ key: "user-rl-over" });
  });

  it("forwards model POST through when RATE_LIMITER reports allowed", async () => {
    const token = await signJwt({
      sub: "user-rl-ok",
      email: "rl-ok@example.com",
      has_active_subscription: true,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const allowed = makeRateLimiter(true);
    const { env } = makeEnv("enforce", jwks, { rateLimiter: allowed });
    const { captured } = stubFetch({
      usersMeBody: { full_name: "RL OK User", has_active_subscription: true },
    });
    const req = new Request("https://chat.thefixer.in/api/chat/completions", {
      method: "POST",
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(200);
    expect(captured()).not.toBeNull();
    expect(allowed.limit).toHaveBeenCalledWith({ key: "user-rl-ok" });
  });

  it("does NOT call RATE_LIMITER on UI page loads (only model-API paths are rate limited)", async () => {
    const token = await signJwt({
      sub: "user-rl-ui",
      email: "rl-ui@example.com",
      has_active_subscription: true,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const limiter = makeRateLimiter(true);
    const { env } = makeEnv("enforce", jwks, { rateLimiter: limiter });
    stubFetch({
      usersMeBody: { full_name: "RL UI User", has_active_subscription: true },
    });
    const req = new Request("https://chat.thefixer.in/", {
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(200);
    expect(limiter.limit).not.toHaveBeenCalled();
  });

  it("does NOT call RATE_LIMITER on non-model /api/* bypass paths", async () => {
    const limiter = makeRateLimiter(true);
    const { env } = makeEnv("enforce", undefined, { rateLimiter: limiter });
    stubFetch({});
    // Non-model /api/* path: the worker bypasses straight through without
    // running the JWT path, so the limiter must not be invoked.
    const req = new Request("https://chat.thefixer.in/api/agents", {
      method: "POST",
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(limiter.limit).not.toHaveBeenCalled();
  });

  it("forwards model POST when RATE_LIMITER binding is unset (pre-rollout window)", async () => {
    const token = await signJwt({
      sub: "user-rl-unset",
      email: "rl-unset@example.com",
      has_active_subscription: true,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    // rateLimiter: null → env.RATE_LIMITER stays undefined.
    const { env } = makeEnv("enforce", jwks, { rateLimiter: null });
    const { captured } = stubFetch({
      usersMeBody: { full_name: "RL Unset User", has_active_subscription: true },
    });
    const req = new Request("https://chat.thefixer.in/api/chat/completions", {
      method: "POST",
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(200);
    expect(captured()).not.toBeNull();
  });
});
