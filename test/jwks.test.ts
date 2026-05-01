import { describe, expect, it, vi, beforeEach } from "vitest";
import { fetchJwks } from "../src/jwks";

const SAMPLE_JWKS = {
  keys: [
    { kty: "RSA", kid: "key1", n: "abc", e: "AQAB", alg: "RS256", use: "sig" },
  ],
};

describe("fetchJwks", () => {
  let kv: KVNamespace;

  beforeEach(() => {
    kv = {
      get: vi.fn(),
      put: vi.fn(),
      delete: vi.fn(),
    } as unknown as KVNamespace;
    globalThis.fetch = vi.fn(async () =>
      new Response(JSON.stringify(SAMPLE_JWKS), { status: 200 })
    ) as typeof fetch;
  });

  it("returns cached JWKS when present", async () => {
    (kv.get as ReturnType<typeof vi.fn>).mockResolvedValue(JSON.stringify(SAMPLE_JWKS));
    const jwks = await fetchJwks("https://example/.well-known/jwks.json", kv);
    expect(jwks.keys).toHaveLength(1);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("fetches and caches JWKS on cache miss", async () => {
    (kv.get as ReturnType<typeof vi.fn>).mockResolvedValue(null);
    const jwks = await fetchJwks("https://example/.well-known/jwks.json", kv);
    expect(jwks.keys).toHaveLength(1);
    expect(globalThis.fetch).toHaveBeenCalledOnce();
    expect(kv.put).toHaveBeenCalledWith(
      "jwks",
      JSON.stringify(SAMPLE_JWKS),
      { expirationTtl: 86400 }
    );
  });

  it("returns stale cache on fetch failure", async () => {
    (kv.get as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce(JSON.stringify(SAMPLE_JWKS));
    globalThis.fetch = vi.fn(async () => new Response("upstream error", { status: 500 })) as typeof fetch;
    const jwks = await fetchJwks("https://example/.well-known/jwks.json", kv, { staleKey: "jwks_stale" });
    expect(jwks.keys).toHaveLength(1);
  });

  it("throws when no cache and fetch fails", async () => {
    (kv.get as ReturnType<typeof vi.fn>).mockResolvedValue(null);
    globalThis.fetch = vi.fn(async () => new Response("error", { status: 500 })) as typeof fetch;
    await expect(fetchJwks("https://example/.well-known/jwks.json", kv)).rejects.toThrow(/JWKS/);
  });
});
