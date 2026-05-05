import { describe, expect, it, vi, beforeEach } from "vitest";
import { deriveSubscriptionStatus, fetchUsersMe } from "../src/users";

describe("deriveSubscriptionStatus", () => {
  it("returns active when has_active_subscription is true", () => {
    expect(
      deriveSubscriptionStatus({ has_active_subscription: true }),
    ).toBe("active");
  });

  it("returns expired when has_active_subscription is false", () => {
    expect(
      deriveSubscriptionStatus({ has_active_subscription: false }),
    ).toBe("expired");
  });

  it("returns expired when has_active_subscription is missing from the body", () => {
    expect(deriveSubscriptionStatus({})).toBe("expired");
  });
});

interface KvHandle {
  store: Map<string, string>;
  get: ReturnType<typeof vi.fn>;
  put: ReturnType<typeof vi.fn>;
  delete: ReturnType<typeof vi.fn>;
}

function makeKv(): KvHandle {
  const store = new Map<string, string>();
  const get = vi.fn(async (key: string) => store.get(key) ?? null);
  const put = vi.fn(async (key: string, value: string) => {
    store.set(key, value);
  });
  const del = vi.fn(async (key: string) => {
    store.delete(key);
  });
  return { store, get, put, delete: del };
}

describe("fetchUsersMe", () => {
  let kv: KvHandle;

  beforeEach(() => {
    kv = makeKv();
  });

  it("returns null when the backend responds 5xx", async () => {
    globalThis.fetch = vi.fn(async () => new Response("err", { status: 503 })) as typeof fetch;
    const result = await fetchUsersMe({
      apiBaseUrl: "https://api.example",
      jwt: "tok",
      userId: "u1",
      cache: kv as unknown as KVNamespace,
    });
    expect(result).toBeNull();
    expect(kv.put).not.toHaveBeenCalled();
  });

  it("returns null when the backend responds 401", async () => {
    globalThis.fetch = vi.fn(async () => new Response("unauth", { status: 401 })) as typeof fetch;
    const result = await fetchUsersMe({
      apiBaseUrl: "https://api.example",
      jwt: "tok",
      userId: "u1",
      cache: kv as unknown as KVNamespace,
    });
    expect(result).toBeNull();
  });

  it("returns null when fetch throws (network error)", async () => {
    globalThis.fetch = vi.fn(async () => {
      throw new Error("ENETUNREACH");
    }) as typeof fetch;
    const result = await fetchUsersMe({
      apiBaseUrl: "https://api.example",
      jwt: "tok",
      userId: "u1",
      cache: kv as unknown as KVNamespace,
    });
    expect(result).toBeNull();
  });

  it("normalises an empty-string full_name to null", async () => {
    globalThis.fetch = vi.fn(async () =>
      new Response(JSON.stringify({ full_name: "", has_active_subscription: true }), {
        status: 200,
      }),
    ) as typeof fetch;
    const result = await fetchUsersMe({
      apiBaseUrl: "https://api.example",
      jwt: "tok",
      userId: "u1",
      cache: kv as unknown as KVNamespace,
    });
    expect(result).toEqual({ name: null, subscription_status: "active" });
  });

  it("sends Authorization: Bearer header with the JWT", async () => {
    let capturedHeaders: Headers | null = null;
    globalThis.fetch = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
      capturedHeaders = new Headers(init?.headers);
      return new Response(JSON.stringify({ full_name: "X", has_active_subscription: true }), {
        status: 200,
      });
    }) as typeof fetch;
    await fetchUsersMe({
      apiBaseUrl: "https://api.example",
      jwt: "the-jwt",
      userId: "u1",
      cache: kv as unknown as KVNamespace,
    });
    expect(capturedHeaders!.get("Authorization")).toBe("Bearer the-jwt");
  });

  it("respects a custom ttlSeconds when writing to KV", async () => {
    globalThis.fetch = vi.fn(async () =>
      new Response(JSON.stringify({ full_name: "X", has_active_subscription: true }), {
        status: 200,
      }),
    ) as typeof fetch;
    await fetchUsersMe({
      apiBaseUrl: "https://api.example",
      jwt: "tok",
      userId: "u1",
      cache: kv as unknown as KVNamespace,
      ttlSeconds: 60,
    });
    expect(kv.put).toHaveBeenCalledWith(
      "users_me:u1",
      expect.any(String),
      expect.objectContaining({ expirationTtl: 60 }),
    );
  });
});
