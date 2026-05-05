# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

## What this is

Cloudflare Worker that gates `chat.thefixer.in` (Open WebUI) by reading the
Supabase JWT cookie and checking the `has_active_subscription` claim.

## Commands

```bash
npm install          # install deps
npm run dev          # local dev with wrangler
npm run test         # vitest
npm run deploy       # wrangler deploy (CI does this on push to main)
```

## Architecture

- `src/index.ts`: fetch handler (Worker entry)
- `src/jwt.ts`: JWT verify + claim extraction (uses `jose`)
- `src/jwks.ts`: JWKS fetch + KV cache
- `src/users.ts`: `/v1/users/me` fetch + KV cache (5 min) + subscription_status derivation
- `src/config.ts`: env-derived constants

`JWKS_CACHE` is a Workers KV namespace with 24h TTL on the cached JWKS document; `users_me:<sub>` keys in the same namespace cache the `/v1/users/me` lookup with a 60s TTL (reduced from 5min in F12 to shrink the post-cancellation staleness window).

Per-request flow (Round 6 / T6.1):
1. Verify Supabase JWT cookie (existing).
2. Fetch `/v1/users/me` from `API_BASE_URL` (KV-cached) to derive `name` and `subscription_status` (active | trial | demo | expired).
3. If backend reports `expired`, redirect to `UPGRADE_REDIRECT` even when the JWT claim says active (PayPal sub status flipped between token issuance and now).
4. Forward `X-Forwarded-Email`, `X-Forwarded-User`, `X-Forwarded-Name`, and `X-Forwarded-Subscription-Status` to LibreChat. Backend failure (5xx, 401, network error) falls back to forwarding email + sub only so chat does not break during a backend outage.

## Deploy

`.github/workflows/deploy.yml` runs `wrangler deploy` on push to main.

## Required env (in wrangler.toml `[vars]` and Workers Secrets)

`SUPABASE_URL`, `LOGIN_REDIRECT`, `UPGRADE_REDIRECT`, `WORKER_MODE`, `API_BASE_URL`.
