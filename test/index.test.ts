import { describe, expect, it, vi, beforeAll, beforeEach } from "vitest";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import worker from "../src/index";
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

function makeEnv(
  mode: "shadow" | "enforce",
  jwksOverride?: string,
): { env: WorkerEnv; kv: KvHandle } {
  const jwksValue = jwksOverride ?? SAMPLE_JWKS;
  const kv = makeKv(jwksValue);
  const env: WorkerEnv = {
    JWKS_CACHE: kv as unknown as KVNamespace,
    SUPABASE_URL: "https://example.supabase.co",
    LOGIN_REDIRECT: "https://thefixer.in/login",
    UPGRADE_REDIRECT: "https://thefixer.in/app/billing/upgrade",
    WORKER_MODE: mode,
    API_BASE_URL: "https://api.thefixer.in",
  };
  return { env, kv };
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

describe("Round 6 / T6.1 name + subscription forwarding", () => {
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

  it("forwards trial subscription status when in_trial_window is true", async () => {
    const token = await signJwt({
      sub: "user-trial",
      email: "trial@example.com",
      has_active_subscription: true,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const { env } = makeEnv("enforce", jwks);
    const { captured } = stubFetch({
      usersMeBody: {
        full_name: "Trial User",
        has_active_subscription: false,
        in_trial_window: true,
      },
    });
    const req = new Request("https://chat.thefixer.in/", {
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(200);
    const fwd = captured();
    expect(fwd!.headers.get("X-Forwarded-Subscription-Status")).toBe("trial");
  });

  it("forwards demo subscription status when only in_demo_window is true", async () => {
    const token = await signJwt({
      sub: "user-demo",
      email: "demo@example.com",
      has_active_subscription: true,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const { env } = makeEnv("enforce", jwks);
    const { captured } = stubFetch({
      usersMeBody: {
        full_name: "Demo User",
        has_active_subscription: false,
        in_demo_window: true,
      },
    });
    const req = new Request("https://chat.thefixer.in/", {
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(200);
    const fwd = captured();
    expect(fwd!.headers.get("X-Forwarded-Subscription-Status")).toBe("demo");
  });

  it("redirects to upgrade when backend reports subscription_status=expired even if JWT claim says active", async () => {
    const token = await signJwt({
      sub: "user-expired",
      email: "expired@example.com",
      has_active_subscription: true,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const { env } = makeEnv("enforce", jwks);
    stubFetch({
      usersMeBody: {
        full_name: "Expired User",
        has_active_subscription: false,
        in_trial_window: false,
        in_demo_window: false,
      },
    });
    const req = new Request("https://chat.thefixer.in/", {
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(302);
    expect(resp.headers.get("Location")).toContain("/app/billing/upgrade");
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
      expect.objectContaining({ expirationTtl: 300 }),
    );

    // Second request should hit the KV cache and not re-call the backend.
    const req2 = new Request("https://chat.thefixer.in/foo", {
      headers: { cookie: `sb-access-token=${token}` },
    });
    await worker.fetch(req2, env, ctx as unknown as ExecutionContext);
    expect(usersMeCalls).toBe(1);
  });
});
