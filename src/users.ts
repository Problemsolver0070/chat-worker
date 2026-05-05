/**
 * Users-me fetcher: calls `GET /v1/users/me` on api.thefixer.in with the
 * caller's JWT, derives `name` and `subscription_status`, and caches the
 * result in Workers KV for a short TTL so we do not hit the backend on
 * every chat request.
 *
 * Round 6 / T6.1 of the name + referral + card-upfront-trial plan. The
 * response is forwarded to the LibreChat origin as `x-forwarded-name`
 * and `x-forwarded-subscription-status`. When the backend returns 5xx,
 * 401, or any other failure, the helper returns `null` and the caller
 * falls back to the existing email-only header set so an outage on
 * `/v1/users/me` does not break chat access.
 */
export type SubscriptionStatus = "active" | "expired";

export interface UsersMeResult {
  name: string | null;
  subscription_status: SubscriptionStatus;
}

interface UsersMeResponse {
  full_name?: string | null;
  has_active_subscription?: boolean;
}

const CACHE_KEY_PREFIX = "users_me:";
const DEFAULT_TTL_SECONDS = 300;

/**
 * Derive the public subscription_status from the backend response.
 * The backend now folds admin_chat_grant, PayPal sub status, and
 * comp_until into a single `has_active_subscription` boolean. The
 * worker just maps it to "active" or "expired".
 */
export function deriveSubscriptionStatus(body: UsersMeResponse): SubscriptionStatus {
  return body.has_active_subscription ? "active" : "expired";
}

/**
 * Fetch `/v1/users/me`, with KV-cached read-through. `userId` (Supabase
 * sub claim) is the cache key so concurrent requests from the same user
 * collapse onto a single backend call within the TTL window.
 *
 * Returns `null` on any failure (network error, non-2xx, malformed
 * body) so the caller can fall back gracefully. Logs the failure mode
 * for observability.
 */
export async function fetchUsersMe(opts: {
  apiBaseUrl: string;
  jwt: string;
  userId: string;
  cache: KVNamespace;
  ttlSeconds?: number;
}): Promise<UsersMeResult | null> {
  const ttl = opts.ttlSeconds ?? DEFAULT_TTL_SECONDS;
  const cacheKey = `${CACHE_KEY_PREFIX}${opts.userId}`;

  const cached = await opts.cache.get(cacheKey);
  if (cached) {
    try {
      return JSON.parse(cached) as UsersMeResult;
    } catch {
      // Corrupt cache entry, fall through to fresh fetch.
    }
  }

  let resp: Response;
  try {
    resp = await fetch(`${opts.apiBaseUrl}/v1/users/me`, {
      headers: { Authorization: `Bearer ${opts.jwt}` },
    });
  } catch (err) {
    console.log(JSON.stringify({
      event: "users_me_fetch_failed",
      reason: "network_error",
      message: (err as Error).message,
    }));
    return null;
  }

  if (!resp.ok) {
    console.log(JSON.stringify({
      event: "users_me_fetch_failed",
      reason: "non_2xx",
      status: resp.status,
    }));
    return null;
  }

  let body: UsersMeResponse;
  try {
    body = (await resp.json()) as UsersMeResponse;
  } catch (err) {
    console.log(JSON.stringify({
      event: "users_me_fetch_failed",
      reason: "malformed_body",
      message: (err as Error).message,
    }));
    return null;
  }

  const result: UsersMeResult = {
    name: typeof body.full_name === "string" && body.full_name.length > 0
      ? body.full_name
      : null,
    subscription_status: deriveSubscriptionStatus(body),
  };

  try {
    await opts.cache.put(cacheKey, JSON.stringify(result), { expirationTtl: ttl });
  } catch (err) {
    // Cache write failure is non-fatal; the next request just re-fetches.
    console.log(JSON.stringify({
      event: "users_me_cache_write_failed",
      message: (err as Error).message,
    }));
  }

  return result;
}
