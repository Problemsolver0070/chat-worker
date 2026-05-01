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
  await cache.put(opts.staleKey ?? STALE_CACHE_KEY, text);
  return jwks;
}

async function tryStale(cache: KVNamespace, key: string): Promise<Jwks> {
  const stale = await cache.get(key);
  if (!stale) {
    throw new Error("JWKS unavailable: no cache and upstream fetch failed");
  }
  return JSON.parse(stale) as Jwks;
}
