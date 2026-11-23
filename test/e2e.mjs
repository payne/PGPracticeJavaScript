// End-to-end test: drives every exercise with the real `gpg` binary in a throwaway GNUPGHOME.
// Usage: BASE=http://127.0.0.1:8787 KEYTYPE=default|rsa3072 node test/e2e.mjs
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const BASE = process.env.BASE ?? 'http://127.0.0.1:8787';
const KEYTYPE = process.env.KEYTYPE ?? 'default';
const home = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'pgpractice-e2e-'));
const env = { ...process.env, GNUPGHOME: home };
let cookie = '';
let failures = 0;

function gpg(args, input) {
  const r = spawnSync('gpg', ['--batch', '--yes', '--pinentry-mode', 'loopback', '--passphrase', '', '--trust-model', 'always', ...args], {
    input,
    env,
    cwd: home,
    encoding: 'utf8',
  });
  return { out: r.stdout, err: r.stderr, code: r.status };
}

async function api(path, body, method) {
  const res = await fetch(BASE + path, {
    method: method ?? (body ? 'POST' : 'GET'),
    headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...(cookie ? { cookie } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const setCookie = res.headers.get('set-cookie');
  if (setCookie) cookie = setCookie.split(';')[0];
  const text = await res.text();
  try {
    return { status: res.status, ...JSON.parse(text) };
  } catch {
    return { status: res.status, text };
  }
}

function check(name, cond, info) {
  if (cond) console.log(`  ✓ ${name}`);
  else {
    failures++;
    console.log(`  ✗ ${name}`, info !== undefined ? JSON.stringify(info, null, 2) : '');
  }
}

const t0 = Date.now();
try {
  console.log(`E2E against ${BASE} with key type ${KEYTYPE} (GNUPGHOME=${home})`);

  // 0. Key generation & upload
  gpg(['--quick-gen-key', 'Test User <test@example.com>', KEYTYPE, 'default', '1y']);
  if (KEYTYPE.startsWith('rsa')) {
    const f = gpg(['--with-colons', '--list-keys']).out.match(/^fpr:+([0-9A-F]{40}):/m)[1];
    gpg(['--quick-add-key', f, KEYTYPE, 'encr', '1y']);
  }
  const myFpr = gpg(['--with-colons', '--list-keys']).out.match(/^fpr:+([0-9A-F]{40}):/m)[1];
  const pub = gpg(['--armor', '--export', myFpr]).out;

  const priv = gpg(['--armor', '--export-secret-keys', myFpr]).out;
  const privRes = await api('/api/keys', { armored: priv });
  check('private key upload is rejected', privRes.status === 400 && /PRIVATE/.test(privRes.error), privRes);

  const up = await api('/api/keys', { armored: pub });
  check('public key upload', up.status === 200 && up.key.fingerprint === myFpr, up);

  // Decrypt challenge
  const dec = gpg(['--decrypt'], up.challenge);
  // The server key is not imported yet, so gpg cannot check the signature at this point.
  check('challenge decrypts (signature from server key present)', dec.code !== null && /Can't check signature: No public key|Good signature/.test(dec.err), dec.err);
  const code = dec.out.match(/\b([A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4})\b/)[1];
  const bad = await api('/api/keys/verify', { fingerprint: myFpr, code: 'AAAA-AAAA-AAAA' });
  check('wrong code rejected', bad.status === 400, bad);
  const ver = await api('/api/keys/verify', { fingerprint: myFpr, code: code.toLowerCase() });
  check('verify + session cookie', ver.ok && cookie.startsWith('pgps='), ver);

  // 1. Server key / fingerprint
  const asc = await fetch(BASE + '/api/server-key.asc').then((r) => r.text());
  gpg(['--import'], asc);
  const serverFpr = gpg(['--with-colons', '--fingerprint', 'practice@pgpractice.appfarms.org']).out.match(/^fpr:+([0-9A-F]{40}):/m)[1];
  check('fingerprint (partial rejected)', !(await api('/api/exercises/fingerprint/submit', { answer: serverFpr.slice(-16) })).ok);
  const fp = await api('/api/exercises/fingerprint/submit', { answer: serverFpr.replace(/(.{4})/g, '$1 ') });
  check('fingerprint exercise', fp.ok, fp);

  // WKD
  // Hash computed by GnuPG itself, so this cross-checks our z-base-32 implementation.
  const wks = ['gpg-wks-client', '/usr/lib/gnupg/gpg-wks-client', '/usr/libexec/gpg-wks-client']
    .map((bin) => spawnSync(bin, ['--print-wkd-hash', 'practice@pgpractice.appfarms.org'], { encoding: 'utf8' }))
    .find((r) => r.status === 0);
  const hash = wks ? wks.stdout.split(' ')[0] : 'unknown';
  const wkd = await fetch(BASE + '/.well-known/openpgpkey/hu/' + hash + '?l=practice');
  check('WKD serves binary key', wkd.status === 200 && (await wkd.arrayBuffer()).byteLength > 100);

  // 3. Encrypt
  const encSelf = gpg(['--armor', '--encrypt', '--recipient', myFpr], 'hi').out;
  const es = await api('/api/exercises/encrypt/submit', { armored: encSelf });
  check('encrypt-to-self rejected with hint', es.status === 400 && /not to the server/.test(es.error), es);
  const enc = gpg(['--armor', '--encrypt', '--recipient', 'practice@pgpractice.appfarms.org'], 'Hello PGPractice\n').out;
  const e1 = await api('/api/exercises/encrypt/submit', { armored: enc });
  check('encrypt exercise', e1.ok && e1.plaintext.includes('Hello PGPractice'), e1);

  // 4. Clearsign
  const cs = await api('/api/exercises/clearsign/start', {});
  const signed = gpg(['--clearsign'], `My phrase: ${cs.phrase}\n`).out;
  const csNo = await api('/api/exercises/clearsign/submit', { armored: gpg(['--clearsign'], 'nothing\n').out });
  check('clearsign without phrase fails', csNo.ok === false, csNo);
  const csr = await api('/api/exercises/clearsign/submit', { armored: signed });
  check('clearsign exercise', csr.ok, csr);

  // 5. Detached
  const ds = await api('/api/exercises/detached/start', {});
  writeFileSync(join(home, 'practice.txt'), ds.file.content);
  gpg(['--armor', '--detach-sign', 'practice.txt']);
  const dr = await api('/api/exercises/detached/submit', { armored: readFileSync(join(home, 'practice.txt.asc'), 'utf8') });
  check('detached exercise', dr.ok, dr);

  // 6. Sign + encrypt
  const se = await api('/api/exercises/sign-encrypt/start', {});
  const encOnly = gpg(['--armor', '--encrypt', '--recipient', 'practice@pgpractice.appfarms.org'], se.phrase).out;
  const seNo = await api('/api/exercises/sign-encrypt/submit', { armored: encOnly });
  check('encrypt-only rejected for sign-encrypt', seNo.ok === false && /not signed/.test(seNo.headline), seNo);
  const sem = gpg(['--armor', '--sign', '--encrypt', '--recipient', 'practice@pgpractice.appfarms.org'], `My phrase: ${se.phrase}\n`).out;
  const ser = await api('/api/exercises/sign-encrypt/submit', { armored: sem });
  check('sign-encrypt exercise', ser.ok, ser);

  // 7. Read reply
  const rr = await api('/api/exercises/read-reply/start', {});
  const rd = gpg(['--decrypt'], rr.blocks[0].content);
  check('reply has good server signature', /Good signature/.test(rd.err), rd.err);
  const word = rd.out.match(/secret word is: (\S+)/)[1];
  const rrr = await api('/api/exercises/read-reply/submit', { answer: word });
  check('read-reply exercise', rrr.ok, rrr);

  // 8. Tamper
  const tp = await api('/api/exercises/tamper/start', {});
  const badIdx = tp.blocks.map((b, i) => (gpg(['--verify'], b.content).code === 0 ? -1 : i)).filter((i) => i >= 0);
  check('tamper has 1-3 bad messages', badIdx.length >= 1 && badIdx.length <= 3, badIdx);
  const wrong = await api('/api/exercises/tamper/submit', { choices: [] });
  check('tamper wrong answer rejected', wrong.ok === false, wrong);
  const tr = await api('/api/exercises/tamper/submit', { choices: badIdx });
  check('tamper exercise', tr.ok, tr);

  // 9. Key update
  const nochange = await api('/api/exercises/key-update/submit', { armored: pub });
  check('key-update with no change fails', nochange.ok === false, nochange);
  gpg(['--quick-set-expire', myFpr, '2y']);
  gpg(['--quick-add-uid', myFpr, 'Test User <second@example.com>']);
  const ku = await api('/api/exercises/key-update/submit', { armored: gpg(['--armor', '--export', myFpr]).out });
  check('key-update exercise', ku.ok && ku.details.some((d) => /Expiry/.test(d)) && ku.details.some((d) => /second@/.test(d)), ku);

  // 10. Revoke (use GnuPG's auto-generated cert, which has the ':' guard prefix)
  const revFile = readdirSync(join(home, 'openpgp-revocs.d')).find((f) => f.startsWith(myFpr));
  const rev = readFileSync(join(home, 'openpgp-revocs.d', revFile), 'utf8');
  const rv = await api('/api/exercises/revoke/submit', { armored: rev });
  check('revoke exercise', rv.ok, rv);

  // 11. Certify
  const lsig = gpg(['--quick-lsign-key', serverFpr]);
  const lexp = await api('/api/exercises/certify/submit', { armored: gpg(['--armor', '--export', serverFpr]).out });
  check('local signature is not accepted', lexp.ok === false, lexp);
  gpg(['--delete-keys', serverFpr]);
  gpg(['--import'], asc);
  gpg(['--quick-sign-key', serverFpr]);
  const cr = await api('/api/exercises/certify/submit', { armored: gpg(['--armor', '--export', serverFpr]).out });
  check('certify exercise', cr.ok, { cr, lsig: lsig.err });

  // Progress
  const me = await api('/api/me');
  check('all 12 exercises complete', Object.keys(me.progress ?? {}).length === 12, me.progress);

  // Returning user
  const again = await api('/api/keys', { armored: pub });
  check('returning user gets new challenge', again.returning === true && /BEGIN PGP MESSAGE/.test(again.challenge), again);

  // Forget me
  const del = await api('/api/me', {}, 'DELETE');
  check('delete my data', del.ok, del);
  const after = await api('/api/me');
  check('signed out after delete', after.signedIn === false, after);

  // CSRF: non-JSON post rejected
  const form = await fetch(BASE + '/api/keys', { method: 'POST', body: 'armored=x', headers: { 'content-type': 'application/x-www-form-urlencoded' } });
  check('non-JSON POST rejected', form.status === 415);
} catch (e) {
  failures++;
  console.error('E2E crashed:', e);
} finally {
  rmSync(home, { recursive: true, force: true });
}
console.log(failures ? `\n${failures} check(s) FAILED` : `\nAll checks passed (${((Date.now() - t0) / 1000).toFixed(1)}s)`);
process.exit(failures ? 1 : 0);
