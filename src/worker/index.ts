import { Hono, type Context } from 'hono';
import type { Env } from './env';
import { Store } from './db';
import { GRADERS, makeLoginChallenge, type Ctx } from './exercises';
import { UserError, assertInput, describeKey, fpr, groupFpr, openpgp, readUserPublicKey, serverPrivateKey, wkdHash } from './pgp';
import { clearSessionCookie, makeSessionCookie, readSession } from './session';
import { normalizeCode, normalizeFpr, sha256Hex } from './util';
import { EXERCISE_IDS, getExercise } from '../shared/exercises';

type App = { Bindings: Env; Variables: { store: Store } };
const app = new Hono<App>();

const isSecure = (c: Context<App>) => new URL(c.req.url).protocol === 'https:';
const clientIp = (c: Context<App>) => c.req.header('cf-connecting-ip') ?? 'local';

app.use('/api/*', async (c, next) => {
  c.set('store', new Store(c.env.DB));
  if (c.req.method !== 'GET' && c.req.method !== 'HEAD') {
    // JSON-only writes: blocks simple cross-site form posts (CSRF) in addition to SameSite cookies.
    if (!(c.req.header('content-type') ?? '').startsWith('application/json')) {
      return c.json({ error: 'Expected application/json' }, 415);
    }
    if (!(await c.get('store').rateLimit(`ip:${clientIp(c)}`, 120, 600))) {
      return c.json({ error: 'Too many requests — please slow down and try again in a few minutes.' }, 429);
    }
  }
  await next();
  c.header('Cache-Control', 'no-store');
});

app.onError((err, c) => {
  if (err instanceof UserError) return c.json({ error: err.message, hint: err.hint }, err.status as 400);
  console.error(err);
  return c.json({ error: 'Internal error' }, 500);
});

async function body(c: Context<App>): Promise<Record<string, unknown>> {
  try {
    const b = await c.req.json();
    return b && typeof b === 'object' ? b : {};
  } catch {
    throw new UserError('Invalid JSON body.');
  }
}

async function serverKey(c: Context<App>) {
  return serverPrivateKey(c.env.SERVER_PRIVATE_KEY);
}

async function requireUser(c: Context<App>): Promise<Ctx> {
  const f = await readSession(c.env.SESSION_SECRET, c.req.header('cookie'));
  if (!f) throw new UserError('Please sign in first: upload your key and decrypt the challenge on the home page.', undefined, 401);
  const store = c.get('store');
  const row = await store.getKey(f);
  if (!row || !row.verified_at) throw new UserError('Your session has expired (data is deleted after 30 days of inactivity). Please upload your key again.', undefined, 401);
  const userKey = await openpgp.readKey({ armoredKey: row.armored });
  return { store, fpr: f, userKey, serverKey: await serverKey(c), serverEmail: c.env.SERVER_EMAIL };
}

// --- Server key ------------------------------------------------------------------------------

app.get('/api/server-key', async (c) => {
  const key = (await serverKey(c)).toPublic();
  return c.json({ fingerprint: fpr(key), grouped: groupFpr(fpr(key)), email: c.env.SERVER_EMAIL, armored: key.armor() });
});

app.get('/api/server-key.asc', async (c) => {
  const key = (await serverKey(c)).toPublic();
  return c.text(key.armor(), 200, { 'Content-Type': 'application/pgp-keys; charset=utf-8' });
});

// --- Key upload / sign-in ------------------------------------------------------------------------

app.post('/api/keys', async (c) => {
  const store = c.get('store');
  if (!(await store.rateLimit(`upload:${clientIp(c)}`, 20, 3600))) {
    throw new UserError('Too many key uploads from your network. Try again in an hour.', undefined, 429);
  }
  const text = assertInput((await body(c)).armored, 'public key');
  const userKey = await readUserPublicKey(text);
  const f = fpr(userKey);
  const info = await describeKey(userKey);
  const existing = await store.getKey(f);
  if (!existing || !existing.verified_at) {
    await store.insertKey(f, userKey.armor(), info.uid, info.algo);
  }
  // Encrypt the challenge to the key we have on file (the uploaded one for new users).
  const encryptTo = existing?.verified_at ? await openpgp.readKey({ armoredKey: existing.armored }) : userKey;
  const challenge = await makeLoginChallenge(store, encryptTo, await serverKey(c), new URL(c.req.url).origin);
  return c.json({ key: info, returning: !!existing?.verified_at, challenge });
});

app.post('/api/keys/verify', async (c) => {
  const store = c.get('store');
  const b = await body(c);
  const f = normalizeFpr(String(b.fingerprint ?? ''));
  const code = normalizeCode(String(b.code ?? ''));
  if (f.length < 40 || !code) throw new UserError('Missing fingerprint or code.');
  if (!(await store.rateLimit(`verify:${f}`, 10, 600))) throw new UserError('Too many attempts. Wait 10 minutes and upload your key again.', undefined, 429);
  const ch = await store.getChallenge(f, 'decrypt');
  if (!ch) throw new UserError('No active challenge (they expire after one hour). Upload your key again.');
  if ((await sha256Hex(code)) !== ch.secret_hash) {
    throw new UserError('That code is not correct.', 'Copy the code exactly as it appears in the decrypted message, e.g. ABCD-EFGH-JKLM.');
  }
  await store.deleteChallenge(f, 'decrypt');
  await store.markVerified(f);
  await store.complete(f, 'upload', 'decrypt');
  c.header('Set-Cookie', await makeSessionCookie(c.env.SESSION_SECRET, f, isSecure(c)));
  return c.json({ ok: true });
});

app.post('/api/logout', (c) => {
  c.header('Set-Cookie', clearSessionCookie(isSecure(c)));
  return c.json({ ok: true });
});

// --- Me ----------------------------------------------------------------------------------------

app.get('/api/me', async (c) => {
  const f = await readSession(c.env.SESSION_SECRET, c.req.header('cookie'));
  const store = c.get('store');
  const row = f ? await store.getKey(f) : null;
  if (!f || !row?.verified_at) return c.json({ signedIn: false });
  const retention = Number(c.env.RETENTION_DAYS || 30);
  return c.json({
    signedIn: true,
    fingerprint: f,
    uid: row.primary_uid,
    algo: row.algo,
    progress: await store.progress(f),
    expiresAt: new Date((row.last_active + retention * 86400) * 1000).toISOString(),
  });
});

app.delete('/api/me', async (c) => {
  const { store, fpr: f } = await requireUser(c);
  await store.deleteUser(f);
  c.header('Set-Cookie', clearSessionCookie(isSecure(c)));
  return c.json({ ok: true });
});

// --- Exercises -----------------------------------------------------------------------------------

app.post('/api/exercises/:id/start', async (c) => {
  const id = c.req.param('id');
  const grader = GRADERS[id];
  if (!grader?.start) throw new UserError('Unknown exercise or it has no challenge.', undefined, 404);
  const ctx = await requireUser(c);
  return c.json(await grader.start(ctx));
});

app.post('/api/exercises/:id/submit', async (c) => {
  const id = c.req.param('id');
  const grader = GRADERS[id];
  if (!grader || !getExercise(id)) throw new UserError('Unknown exercise.', undefined, 404);
  const ctx = await requireUser(c);
  if (!(await ctx.store.rateLimit(`submit:${ctx.fpr}`, 60, 600))) throw new UserError('Too many submissions — take a short break.', undefined, 429);
  const result = await grader.grade(ctx, await body(c));
  if (result.ok) await ctx.store.complete(ctx.fpr, id);
  else await ctx.store.touch(ctx.fpr);
  return c.json(result);
});

app.get('/api/exercises', (c) => c.json({ ids: EXERCISE_IDS }));

// --- WKD (direct method) -------------------------------------------------------------------------

app.get('/.well-known/openpgpkey/policy', (c) => c.body('', 200, { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'text/plain' }));

app.get('/.well-known/openpgpkey/hu/:hash', async (c) => {
  const [local] = c.env.SERVER_EMAIL.split('@');
  if (c.req.param('hash') !== (await wkdHash(local))) return c.text('Not found', 404);
  const key = (await serverKey(c)).toPublic();
  return c.body(key.write() as Uint8Array<ArrayBuffer>, 200, {
    'Content-Type': 'application/octet-stream',
    'Access-Control-Allow-Origin': '*',
  });
});

app.all('/api/*', (c) => c.json({ error: 'Not found' }, 404));
app.all('/.well-known/*', (c) => c.text('Not found', 404));

export default {
  fetch: app.fetch,
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(
      new Store(env.DB).purge(Number(env.RETENTION_DAYS || 30)).then((changes) => console.log('purge', changes)),
    );
  },
} satisfies ExportedHandler<Env>;
