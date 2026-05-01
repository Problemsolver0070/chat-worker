import { describe, expect, it, vi, beforeEach } from "vitest";
import worker from "../src/index";
import type { WorkerEnv } from "../src/config";

const SAMPLE_JWKS = JSON.stringify({ keys: [] });

function makeEnv(mode: "shadow" | "enforce"): WorkerEnv {
  const kv = {
    get: vi.fn(async () => SAMPLE_JWKS),
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
});
