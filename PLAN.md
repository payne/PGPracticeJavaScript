# PGPractice — Plan

A web app that helps people practice GPG (GnuPG) by uploading their public key
and exchanging armored messages with a server-side "practice partner".
Runs entirely on the Cloudflare free tier.

## Decisions

| Topic | Decision |
|---|---|
| Hosting | Single Cloudflare Worker + Static Assets |
| Domain | `pgpractice.appfarms.org` (custom domain on the `appfarms.org` zone) |
| Server identity | `PGPractice <practice@pgpractice.appfarms.org>`, Ed25519/Cv25519 |
| Key discovery | WKD direct method on `pgpractice.appfarms.org` |
| Exercises | Web only (no email) |
| Frontend | Vanilla TypeScript, built with Vite, responsive (mobile first) |
| Storage | D1 (SQLite) |
| Retention | Everything expires 30 days after last activity (nightly cron purge) |

## Concept

Users do the real work with the `gpg` CLI on their own machine and paste
ASCII-armored text into the site. The site validates, grades and explains.
No accounts: **the key fingerprint is the identity**, proven by decrypting a
challenge the server encrypts to the uploaded key.

## Architecture

```
Browser (static HTML + vanilla TS)  ──►  Worker (TypeScript, OpenPGP.js)
  - lessons, paste boxes                   - parse/validate keys
  - client-side packet inspector           - encrypt/decrypt/sign/verify
  - private-key paste guard                - per-exercise grading
                                            ├─► D1: keys, challenges, submissions, progress, rate
                                            ├─► Secrets: SERVER_PRIVATE_KEY, SESSION_SECRET
                                            └─► Cron (daily): purge data older than 30 days
```

### Free-tier CPU budget (10 ms/request)
- Server key is Ed25519 + Cv25519 → server-side private-key ops are cheap.
- Server only performs *public* ops with user RSA keys (encrypt to / verify).
- Input capped at 64 KB; heavy parsing for display (packet inspector) runs in the browser.

## Identity / sessions
1. `POST /api/keys` — upload public key → stored *unverified*, returns challenge encrypted to it.
2. `POST /api/keys/verify` — user pastes the decrypted challenge → key *verified*,
   HMAC-signed HttpOnly cookie `{fpr, exp}` is set.
3. Returning users: upload the same key again to receive a fresh challenge.

## Exercises
| # | Id | Exercise | Graded by |
|---|---|---|---|
| 0 | `upload` | Generate & export a key, upload it | Key parses, has encryption subkey, not expired/revoked/weak |
| 1 | `fingerprint` | Import server key, confirm fingerprint | Typed fingerprint matches |
| 2 | `decrypt` | Decrypt the challenge | Matches nonce (also proves ownership) |
| 3 | `encrypt` | Encrypt a message to the server | Server decrypts, echoes plaintext |
| 4 | `clearsign` | Clearsign a message | Valid sig by user's key |
| 5 | `detached` | Detached signature over given text | Valid detached sig over exact text |
| 6 | `sign-encrypt` | Sign + encrypt to the server | Decrypts and inner sig valid by user |
| 7 | `read-reply` | Decrypt & verify server's signed+encrypted reply | Secret word submitted |
| 8 | `tamper` | Identify which signed messages were tampered with | Correct set chosen |
| 9 | `key-update` | Change expiry / add subkey, re-upload | Updated key differs as required |
| 10 | `revoke` | Generate a revocation certificate | Valid revocation sig for the key (not applied) |
| 11 | `certify` | Sign the server's key and upload it | Contains user certification on server UID |

## Data model (D1)
See `migrations/0001_init.sql`: `keys`, `challenges` (one active per key+exercise),
`progress`, `rate`. Submissions are not stored — grading results are returned once.

## API
- `GET  /api/server-key`, `GET /api/server-key.asc`
- `POST /api/keys`, `POST /api/keys/verify`
- `GET  /api/me`, `DELETE /api/me`
- `GET  /api/exercises/:id/start`, `POST /api/exercises/:id/submit`
- `POST /api/logout`
- `GET  /.well-known/openpgpkey/hu/:hash`, `/.well-known/openpgpkey/policy`

## Security
- Private key blocks rejected client-side and server-side.
- Server key stored as Worker secret; revocation cert kept offline.
- Rate limiting via D1 fixed-window counters (per IP and per fingerprint).
- Decrypted plaintext is never stored; submissions store only grading results.
- Strict CSP, no inline scripts, all user content rendered as text.
- Daily cron deletes anything older than 30 days.

## Milestones
1. Scaffold (Wrangler, D1 migration, Vite frontend) ✅
2. Server key, upload, challenge/verify, sessions ✅
3. Exercises 0–7 ✅
4. Exercises 8–11 + packet inspector ✅
5. Hardening: rate limits, CSP, purge cron, forget-me ✅
6. Deploy to `pgpractice.appfarms.org` ✅

## Possible next steps
- Turnstile on key upload if abuse appears (D1 rate limits only for now).
- Email exercises via Cloudflare Email Routing / Email Workers.
- Login by clearsigning a nonce (instead of re-decrypting a challenge).

## Testing
- `npm test` — unit tests (WKD hash vs. GnuPG, sessions, input guard, packet inspector).
- `node test/e2e.mjs` — drives all 12 exercises with the real `gpg` binary, including negative
  cases; run with `KEYTYPE=rsa3072` too. Passes locally and against production.
