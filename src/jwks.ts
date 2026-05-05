export interface JwksKey {
  kty: string;
  kid: string;
  n: string;
  e: string;
  alg: string;
  use: string;
}

export interface Jwks {
  keys: JwksKey[];
}

const CACHE_KEY = "jwks";
const STALE_CACHE_KEY = "jwks_stale";
const TTL_SECONDS = 86400;
// F50: bound the stale-fallback to 7 days. After Supabase rotates a JWKS key,
// the fresh-cache TTL (24h) drops first. If the worker also cannot reach the
// JWKS endpoint for a sustained outage, the stale cache covers the gap, but
// only for a finite window. Past 7d the stale entry expires and JWT
// verification fails (forcing re-auth). This caps the blast radius of a
// compromised-and-rotated key being usable indefinitely.
const STALE_TTL_SECONDS = 7 * 24 * 60 * 60;

export async function fetchJwks(
  jwksUrl: string,
  cache: KVNamespace,
  opts: { staleKey?: string } = {}
): Promise<Jwks> {
  const cached = await cache.get(CACHE_KEY);
  if (cached) {
    return JSON.parse(cached) as Jwks;
  }

  let resp: Response;
  try {
    resp = await fetch(jwksUrl);
  } catch (err) {
    return tryStale(cache, opts.staleKey ?? STALE_CACHE_KEY);
  }

  if (!resp.ok) {
    return tryStale(cache, opts.staleKey ?? STALE_CACHE_KEY);
  }

  const text = await resp.text();
  const jwks = JSON.parse(text) as Jwks;
  await cache.put(CACHE_KEY, text, { expirationTtl: TTL_SECONDS });
  // F50: bound the stale fallback so a compromised+rotated key cannot live
  // in the stale cache forever. KV honors the longer of the two TTLs when
  // the same key is overwritten, so refreshing on every successful fetch
  // is fine.
  await cache.put(opts.staleKey ?? STALE_CACHE_KEY, text, {
    expirationTtl: STALE_TTL_SECONDS,
  });
  return jwks;
}

async function tryStale(cache: KVNamespace, key: string): Promise<Jwks> {
  const stale = await cache.get(key);
  if (!stale) {
    throw new Error("JWKS unavailable: no cache and upstream fetch failed");
  }
  return JSON.parse(stale) as Jwks;
}
