import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import * as openpgp from 'openpgp';
import { wkdHash, assertInput } from '../src/worker/pgp';
import { makeSessionCookie, readSession } from '../src/worker/session';
import { inspect } from '../src/web/inspector';
import { EXERCISES } from '../src/shared/exercises';
import { GRADERS } from '../src/worker/exercises';

describe('wkdHash', () => {
  it('matches gpg-wks-client --print-wkd-hash', async () => {
    expect(await wkdHash('practice')).toBe('hf58j75naoejmnhqds6jsi6356ywxsx5');
    expect(await wkdHash('Practice')).toBe('hf58j75naoejmnhqds6jsi6356ywxsx5');
  });
});

describe('session cookie', () => {
  const secret = 'x'.repeat(48);
  it('round-trips and rejects tampering', async () => {
    const c = (await makeSessionCookie(secret, 'ABCD', true)).split(';')[0];
    expect(await readSession(secret, c)).toBe('ABCD');
    expect(await readSession('y'.repeat(48), c)).toBeNull();
    const [name, val] = c.split('=');
    const [payload, sig] = val.split('.');
    const forged = btoa(JSON.stringify({ f: 'EVIL', e: 9e9 })).replace(/=+$/, '');
    expect(await readSession(secret, `${name}=${forged}.${sig}`)).toBeNull();
    expect(await readSession(secret, `${name}=${payload}.AAAA`)).toBeNull();
  });
});

describe('assertInput', () => {
  it('rejects private keys and strips revocation guard colon', () => {
    expect(() => assertInput('-----BEGIN PGP PRIVATE KEY BLOCK-----\nabc')).toThrow(/PRIVATE/);
    expect(assertInput(':-----BEGIN PGP PUBLIC KEY BLOCK-----\nx')).toMatch(/^-----BEGIN/);
    expect(() => assertInput('x'.repeat(70000))).toThrow(/too large/);
  });
});

describe('packet inspector', () => {
  it('parses an OpenPGP.js-generated key and signed message', async () => {
    const { privateKey, publicKey } = await openpgp.generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ email: 'a@b.c' }] });
    const pub = await inspect(publicKey);
    expect(pub.packets.map((p) => p.tag)).toEqual([6, 13, 2, 14, 2]);
    expect(pub.packets[1].fields[0][1]).toBe('<a@b.c>');
    const priv = await inspect(privateKey);
    expect(priv.packets[0].warning).toMatch(/SECRET/);
    const key = await openpgp.readPrivateKey({ armoredKey: privateKey });
    const cleartext = await openpgp.sign({ message: await openpgp.createCleartextMessage({ text: 'hello\n- dash' }), signingKeys: key });
    const cs = await inspect(cleartext);
    expect(cs.cleartext).toContain('- dash');
    expect(cs.packets[0].tag).toBe(2);
  });

  it('decompresses compressed packets', async () => {
    const { privateKey } = await openpgp.generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ email: 'a@b.c' }] });
    const key = await openpgp.readPrivateKey({ armoredKey: privateKey });
    const msg = await openpgp.sign({
      message: await openpgp.createMessage({ text: 'compressed!' }),
      signingKeys: key,
      config: { preferredCompressionAlgorithm: openpgp.enums.compression.zlib },
    });
    const r = await inspect(msg as string);
    expect(r.packets.map((p) => p.tag)).toContain(11);
  });
});

describe('exercise catalogue', () => {
  it('every exercise needing input has a grader', () => {
    for (const e of EXERCISES) {
      if (e.input !== 'none') expect(GRADERS[e.id], e.id).toBeDefined();
      if (e.hasStart) expect(GRADERS[e.id]?.start, e.id).toBeDefined();
    }
  });
});
