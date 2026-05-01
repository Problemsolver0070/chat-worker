# chat-worker

Cloudflare Worker that gates `chat.thefixer.in` traffic by reading the
Supabase JWT cookie and checking the `has_active_subscription` claim.

## Local dev

```bash
npm install
npm run dev
```

Set `.dev.vars` with at least:

```
SUPABASE_URL=https://btzaudxujnodtikhemar.supabase.co
LOGIN_REDIRECT=http://localhost:5173/login
UPGRADE_REDIRECT=http://localhost:5173/app/billing/upgrade
WORKER_MODE=shadow
```

## Deploy

CI deploys via `wrangler deploy`. See `.github/workflows/deploy.yml`.

## Architecture

`src/index.ts` is the fetch handler. It validates the `sb-access-token`
cookie against Supabase JWKS (cached in `JWKS_CACHE` KV namespace, 24h TTL),
reads the `has_active_subscription` claim, and either forwards to the origin
(via Cloudflare Tunnel) or redirects.

In `WORKER_MODE=shadow`, the Worker logs the gating decision but always
forwards to origin. In `WORKER_MODE=enforce`, it actually redirects unpaid
or unauthenticated users.
