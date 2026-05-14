# chat-worker

Cloudflare Worker in front of `chat.thefixer.in`. It reads the Supabase
JWT cookie and checks `has_active_subscription` before forwarding to
origin.

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
cookie against Supabase JWKS (cached in the `JWKS_CACHE` KV namespace,
24h TTL), reads the `has_active_subscription` claim, and either forwards
to the origin via Cloudflare Tunnel or redirects.

`WORKER_MODE=shadow` logs the gating decision but always forwards to
origin. `WORKER_MODE=enforce` redirects unpaid or unauthenticated users.
Shadow mode exists so config changes can be observed in production
before they affect real users.
