# Session Log — PGPractice

**Dates:** 2026-11-18 (planning) → 2026-11-22 (build & deploy)
**Working directory:** `~/git/PGPractice` (empty at start)
**Outcome:** App planned, built, tested and deployed to https://pgpractice.appfarms.org

---

## 1. Requests

1. *"Plan the creation of a web application that will help people practice GPG (GnuPrivacyGuard)
   by uploading their public keys and exchanging messages with the web application. I'd like it to
   run on the free tier of my CloudFlare account."*
2. *"Use my cloudflare appfarms.org domain. Web only exercises for now. vanilla typescript frontend
   and it should be responsive. Have everything expire after 30 days. Save this plan to PLAN.md and
   build it without prompting me."*
3. *"Be sure to put all of the information from this session into a session log markdown"* → this file.

## 2. Planning phase (2026-11-18)

The initial plan (delivered in chat, later saved as `PLAN.md`) proposed:

- **Concept:** users do real work with the `gpg` CLI and paste ASCII-armored output; the site
  validates, grades and explains. No accounts — the key fingerprint is the identity, proven by
  decrypting a server-encrypted challenge.
- **Architecture:** a single Cloudflare Worker with Static Assets (Hono + OpenPGP.js), D1 for
  storage (free KV only allows ~1k writes/day), a daily Cron Trigger for purging.
- **Free-tier CPU constraint (10 ms/request):** server key is Ed25519/Cv25519 so server-side
  private-key ops are cheap; server only does *public* RSA ops on user keys; input capped at 64 KB;
  packet inspection runs client-side.
- **Curriculum of 12 exercises**, data model, API sketch, security controls, milestones.
- **Open questions** asked of the user: custom domain? email exercises? frontend framework? retention?

### Decisions from the user

| Question | Answer |
|---|---|
| Domain | `appfarms.org` (Cloudflare zone) → deployed as `pgpractice.appfarms.org` |
| Email exercises | No — web only for now |
| Frontend | Vanilla TypeScript, responsive |
| Retention | Everything expires after 30 days |

## 3. Environment observed

- Node v26.7.0, npm 11.19.0, GnuPG 2.4.9 (libgcrypt 1.12.4), Chromium available (headless screenshots)
- Wrangler was not globally installed but an OAuth login already existed (`~/.config/.wrangler`).
  Token scopes included workers/D1/routes write and zone read.
- One Cloudflare account; `appfarms.org` already resolves via Cloudflare; `pgpractice.appfarms.org`
  had no existing DNS record (so no conflict).
- `dig` not installed (used `getent` and DNS-over-HTTPS instead).

## 4. Build steps (2026-11-22)

1. **Saved `PLAN.md`** with the decisions above.
2. **Scaffold:** `git init` (no commits made), `package.json`, `.gitignore`
   (`node_modules/ dist/ .wrangler/ .dev.vars secrets/`).
   Installed: `openpgp@6.3.3`, `hono@4.13.20`; dev: `wrangler@4.166.0`, `vite@8.3.8`,
   `typescript@7.0.2`, `vitest@5.1.1`, `@cloudflare/workers-types@5.20261123.1`.
   npm 11 gated install scripts → approved `esbuild` and `workerd` (recorded in `allowScripts`).
3. **`wrangler.jsonc`:** Worker `pgpractice`, custom domain route `pgpractice.appfarms.org`,
   assets from `./dist` with SPA fallback and `run_worker_first` for `/api/*` and `/.well-known/*`,
   D1 binding `DB`, cron `17 3 * * *`, vars `SERVER_EMAIL=practice@pgpractice.appfarms.org`,
   `RETENTION_DAYS=30`, observability on.
4. **`migrations/0001_init.sql`:** tables `keys`, `challenges` (PK fingerprint+exercise),
   `progress`, `rate`.
5. **Server key:** `scripts/gen-server-key.mjs` generates a v4 Ed25519 + Cv25519 key with
   OpenPGP.js (deliberately *not* gpg, so the key doesn't advertise LibrePGP OCB/AEAD — GnuPG then
   encrypts to it with SEIPDv1 which OpenPGP.js can decrypt). Output in `secrets/`
   (`server-private.asc`, `server-public.asc`, `server-revocation.asc`).
   **Server fingerprint: `B33E 0D92 C805 4E75 A741 F846 5410 6312 F601 BD3C`.**
6. **Shared catalogue** `src/shared/exercises.ts`: titles, steps, commands with placeholders
   (`{SERVER_EMAIL}`, `{SERVER_FPR}`, `{MY_FPR}`, `{ORIGIN}`, `{PHRASE}`), pitfalls, result types.
7. **Worker** (`src/worker/`):
   - `pgp.ts` — input guard (size, private-key rejection, strips GnuPG's `:` prefix on revocation
     certs), key validation (not expired/revoked, RSA ≥ 2048, has encryption subkey), cached server
     key, signature reporting, friendly algorithm names, z-base-32 WKD hash.
   - `session.ts` — stateless HMAC-SHA256 cookie `pgps` (HttpOnly, SameSite=Lax, Secure on https, 30 days).
   - `db.ts` — `Store` class (keys, challenges, progress, purge, fixed-window rate limiting via UPSERT).
   - `exercises.ts` — graders for every exercise + login challenge generator.
   - `index.ts` — Hono routes, JSON-only writes (CSRF defence), rate limits, error handler,
     WKD endpoints, `scheduled()` purge.
8. **Frontend** (`src/web/`): `index.html`, `style.css` (light/dark tokens, responsive grid,
   collapsible exercise nav on mobile), `main.ts` (hash router, home/upload/verify, exercise views,
   copy/download, private-key paste guard), `inspector.ts` (dependency-free OpenPGP packet parser,
   including zlib/zip decompression via `DecompressionStream`), `public/_headers` (CSP, HSTS, etc.),
   `public/favicon.svg`.
9. **Tests:** `test/unit.test.ts` (vitest) and `test/e2e.mjs` (real gpg, throwaway `GNUPGHOME`).
10. **Docs:** `README.md`, updated `PLAN.md`, this `SESSION_LOG.md`.

## 5. Exercises implemented

| # | Id | Grading |
|---|---|---|
| 1 | `upload` | Completed by key upload + verification |
| 2 | `fingerprint` | Typed fingerprint equals server's (partial/short IDs rejected with hint) |
| 3 | `decrypt` | Decrypted login challenge code (also signs the user in) |
| 4 | `encrypt` | Server decrypts; rejects messages not addressed to server; echoes plaintext |
| 5 | `clearsign` | Valid sig by user's key + contains server-issued 3-word phrase |
| 6 | `detached` | Detached sig over a downloaded `practice.txt` (binary or textmode) |
| 7 | `sign-encrypt` | Decrypts, requires valid user signature + phrase |
| 8 | `read-reply` | User submits secret word from a server signed+encrypted message |
| 9 | `tamper` | 4 clearsigned messages, 1–3 altered after signing; user must pick the BAD ones |
| 10 | `key-update` | Same fingerprint, detects new subkeys/UIDs/expiry changes; stores updated key |
| 11 | `revoke` | Valid revocation certificate for user's key (verified, never applied) |
| 12 | `certify` | Server key carrying a valid exportable certification by the user's key |

## 6. API

- `GET /api/server-key`, `GET /api/server-key.asc`
- `POST /api/keys` (upload → challenge), `POST /api/keys/verify` (code → session cookie)
- `GET /api/me`, `DELETE /api/me` (forget me), `POST /api/logout`
- `POST /api/exercises/:id/start`, `POST /api/exercises/:id/submit`, `GET /api/exercises`
- `GET /.well-known/openpgpkey/policy`, `GET /.well-known/openpgpkey/hu/:hash` (WKD direct method;
  hash for `practice` = `hf58j75naoejmnhqds6jsi6356ywxsx5`, confirmed with `gpg-wks-client`)

Rate limits: 120 writes / 10 min per IP; 20 key uploads / hour per IP; 10 verify attempts /
10 min per fingerprint; 60 submissions / 10 min per fingerprint.

## 7. Issues encountered & fixes

| Issue | Fix |
|---|---|
| `applyRevocationCertificate` not in OpenPGP.js typings | Used public `openpgp.revokeKey({ key, revocationCertificate, format: 'object' })` |
| Workers types clash with DOM types in one tsconfig | Split into `tsconfig.worker.json` / `tsconfig.web.json` (+ base) |
| CSP `style-src 'self'` blocks `style` attributes | Helper sets styles through CSSOM (`el.style.cssText`) |
| Inspector timestamp overflow (`* 1000 >>> 0` precedence) | Rewrote `time()` on top of `u32()` |
| Vitest picked up Vite's `root: src/web` | Added `vitest.config.ts` with `root: '.'` |
| E2E: challenge shows "Can't check signature: No public key" | Expected (server key not imported yet); test relaxed and UI note added |
| Mobile: copy buttons overlapped commands | `.code` became a flex row; button no longer absolutely positioned |
| Mobile: large gap above content on exercise pages | `align-content: start` on the grid |
| `--` rendered as ligature in code | `font-variant-ligatures: none` |
| Algorithm shown as `eddsaLegacy (ed25519Legacy)` | `friendlyAlgo()` → e.g. `Ed25519`, `RSA-3072` |
| Browser window resize ignored by tiling WM | Used headless Chromium screenshots at 390 px width |
| `wrangler dev --test-scheduled` route swallowed by SPA asset fallback | Tested `Store.purge` directly via `getPlatformProxy` |
| Local D1 empty after setting real `database_id` | Re-ran `wrangler d1 migrations apply pgpractice --local` |
| Local resolver negatively cached `pgpractice.appfarms.org` | Verified via DoH + `curl --resolve`; resolves publicly |

## 8. Verification results

- **Typecheck:** clean (worker + web).
- **Unit tests:** 6/6 pass (WKD hash matches GnuPG, session tamper rejection, input guard,
  inspector on keys/cleartext/compressed messages, catalogue ↔ graders consistency).
- **E2E (local, `wrangler dev`):** all checks pass for Curve25519 and RSA-3072 keys.
- **E2E (production):** all checks pass for both key types (~7 s per run).
  Includes negatives: private key upload rejected, wrong code, encrypt-to-self, missing phrase,
  encrypt-only for sign-encrypt, wrong tamper answer, unchanged key update, lsign not accepted,
  non-JSON POST → 415.
- **CPU time in production** (sampled via `wrangler tail`): max 6 ms (`POST /api/keys`),
  others 1–5 ms — within the 10 ms free-tier limit. All outcomes `ok`.
- **Purge:** key last active 31 days ago deleted with its progress; 29-day-old key kept.
- **Headers in production:** CSP, HSTS, `X-Content-Type-Options` present; SPA fallback 200;
  unknown API → 404.
- **UI:** checked in Chrome (desktop, dark mode) including sign-in, tamper exercise, packet
  inspector, signed-in home; checked mobile layout via headless Chromium.

## 9. Deployment

| Item | Value |
|---|---|
| Worker | `pgpractice` |
| URLs | https://pgpractice.appfarms.org (custom domain), https://pgpractice.matt-g-payne.workers.dev |
| D1 database | `pgpractice`, id `e15cc47b-bfb8-4354-bfbe-778133ca28c1`, region WNAM |
| Cron | `17 3 * * *` (daily purge) |
| Secrets | `SERVER_PRIVATE_KEY`, `SESSION_SECRET` (type `secret_text`, uploaded with `--secrets-file`) |
| Bundle | 650 KiB total upload / 178 KiB gzip; startup 64 ms |
| First version id | `c84e119d-b8cb-4b35-9ef6-d502eac4371b` |

Commands used:
```sh
npx wrangler d1 create pgpractice
npx wrangler d1 migrations apply pgpractice --remote
npx vite build && npx wrangler deploy --secrets-file secrets/prod-secrets.json
```

## 10. Local-only files (not in git — keep safe)

- `secrets/server-private.asc` — server private key (**back up offline**)
- `secrets/server-revocation.asc` — revocation certificate for the server key
- `secrets/server-public.asc`
- `secrets/prod-secrets.json` — production secrets (private key + production session secret)
- `.dev.vars` — local dev secrets (separate session secret)

## 11. Deviations from the original plan

- **Turnstile** omitted; D1 rate limiting only (listed as a possible next step).
- **No `submissions` table**; grading results are returned once and not stored.
- Server key generated with OpenPGP.js rather than gpg (compatibility reason above).

## 12. Open items / next steps

- Nothing has been committed to git yet (repo initialised only).
- Back up `secrets/` offline.
- Possible enhancements: Turnstile on upload, email exercises via Email Routing/Email Workers,
  login by clearsigning a nonce.
