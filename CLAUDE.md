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
- `src/config.ts`: env-derived constants

`JWKS_CACHE` is a Workers KV namespace with 24h TTL on the cached JWKS document.

## Deploy

`.github/workflows/deploy.yml` runs `wrangler deploy` on push to main.

## Required env (in wrangler.toml `[vars]` and Workers Secrets)

`SUPABASE_URL`, `LOGIN_REDIRECT`, `UPGRADE_REDIRECT`, `WORKER_MODE`.
