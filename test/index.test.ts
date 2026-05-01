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

function makeEnv(mode: "shadow" | "enforce", jwksOverride?: string): WorkerEnv {
  const jwksValue = jwksOverride ?? SAMPLE_JWKS;
  const kv = {
    get: vi.fn(async () => jwksValue),
    put: vi.fn(),
    delete: vi.fn(),
  } as unknown as KVNamespace;
  return {
    JWKS_CACHE: kv,
    SUPABASE_URL: "https://example.supabase.co",
    LOGIN_REDIRECT: "https://thefixer.in/login",
    UPGRADE_REDIRECT: "https://thefixer.in/app/billing/upgrade",
    WORKER_MODE: mode,
  };
}

describe("Worker fetch handler", () => {
  it("redirects to login when sb-access-token cookie missing (enforce)", async () => {
    const req = new Request("https://chat.thefixer.in/");
    const env = makeEnv("enforce");
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(302);
    expect(resp.headers.get("Location")).toContain("https://thefixer.in/login");
  });

  it("forwards through (no redirect) when in shadow mode regardless of claim", async () => {
    const req = new Request("https://chat.thefixer.in/");
    const env = makeEnv("shadow");
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
    const env = makeEnv("enforce", jwks);
    let captured: Request | null = null;
    globalThis.fetch = vi.fn(async (forwarded: Request) => {
      captured = forwarded;
      return new Response("ok", { status: 200 });
    }) as typeof fetch;
    const req = new Request("https://chat.thefixer.in/", {
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(200);
    expect(captured).not.toBeNull();
    expect(captured!.headers.get("X-Forwarded-Email")).toBe("test@example.com");
    expect(captured!.headers.get("X-Forwarded-User")).toBe("user-123");
  });

  it("injects X-Forwarded-Email header in shadow mode when JWT has email claim", async () => {
    const token = await signJwt({
      sub: "user-456",
      email: "shadow@example.com",
      has_active_subscription: false,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const env = makeEnv("shadow", jwks);
    let captured: Request | null = null;
    globalThis.fetch = vi.fn(async (forwarded: Request) => {
      captured = forwarded;
      return new Response("ok", { status: 200 });
    }) as typeof fetch;
    const req = new Request("https://chat.thefixer.in/", {
      headers: { cookie: `sb-access-token=${token}` },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(200);
    expect(captured).not.toBeNull();
    expect(captured!.headers.get("X-Forwarded-Email")).toBe("shadow@example.com");
    expect(captured!.headers.get("X-Forwarded-User")).toBe("user-456");
  });

  it("does not inject X-Forwarded-Email header when no cookie present in shadow mode", async () => {
    const env = makeEnv("shadow");
    let captured: Request | null = null;
    globalThis.fetch = vi.fn(async (forwarded: Request) => {
      captured = forwarded;
      return new Response("ok", { status: 200 });
    }) as typeof fetch;
    const req = new Request("https://chat.thefixer.in/");
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(200);
    expect(captured).not.toBeNull();
    expect(captured!.headers.get("X-Forwarded-Email")).toBeNull();
    expect(captured!.headers.get("X-Forwarded-User")).toBeNull();
  });

  it("strips client-supplied X-Forwarded-Email when no JWT cookie (shadow mode)", async () => {
    const env = makeEnv("shadow");
    let captured: Request | null = null;
    globalThis.fetch = vi.fn(async (forwarded: Request) => {
      captured = forwarded;
      return new Response("ok", { status: 200 });
    }) as typeof fetch;
    const req = new Request("https://chat.thefixer.in/", {
      headers: { "X-Forwarded-Email": "spoofed@example.com" },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(200);
    expect(captured).not.toBeNull();
    expect(captured!.headers.get("X-Forwarded-Email")).toBeNull();
  });

  it("strips client-supplied X-Forwarded-User when no JWT cookie (shadow mode)", async () => {
    const env = makeEnv("shadow");
    let captured: Request | null = null;
    globalThis.fetch = vi.fn(async (forwarded: Request) => {
      captured = forwarded;
      return new Response("ok", { status: 200 });
    }) as typeof fetch;
    const req = new Request("https://chat.thefixer.in/", {
      headers: { "X-Forwarded-User": "spoofed-user-id" },
    });
    const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() };
    const resp = await worker.fetch(req, env, ctx as unknown as ExecutionContext);
    expect(resp.status).toBe(200);
    expect(captured).not.toBeNull();
    expect(captured!.headers.get("X-Forwarded-User")).toBeNull();
  });

  it("strips client-supplied X-Forwarded-Email when JWT cookie is invalid (shadow mode)", async () => {
    const env = makeEnv("shadow");
    let captured: Request | null = null;
    globalThis.fetch = vi.fn(async (forwarded: Request) => {
      captured = forwarded;
      return new Response("ok", { status: 200 });
    }) as typeof fetch;
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
    expect(captured).not.toBeNull();
    expect(captured!.headers.get("X-Forwarded-Email")).toBeNull();
    expect(captured!.headers.get("X-Forwarded-User")).toBeNull();
  });

  it("replaces client-supplied X-Forwarded-Email with JWT claim email when JWT is valid (enforce mode)", async () => {
    const token = await signJwt({
      sub: "user-789",
      email: "trusted@example.com",
      has_active_subscription: true,
    });
    const jwks = JSON.stringify({ keys: [publicJwk] });
    const env = makeEnv("enforce", jwks);
    let captured: Request | null = null;
    globalThis.fetch = vi.fn(async (forwarded: Request) => {
      captured = forwarded;
      return new Response("ok", { status: 200 });
    }) as typeof fetch;
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
    expect(captured).not.toBeNull();
    expect(captured!.headers.get("X-Forwarded-Email")).toBe("trusted@example.com");
    expect(captured!.headers.get("X-Forwarded-User")).toBe("user-789");
  });
});
