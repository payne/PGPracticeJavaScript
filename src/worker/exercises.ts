import type { PublicKey, PrivateKey } from 'openpgp';
import type { GradeResult, StartResult } from '../shared/exercises';
import type { Store } from './db';
import {
  openpgp,
  UserError,
  assertInput,
  checkSignatures,
  describeSig,
  encryptAndSign,
  clearsign,
  errMsg,
  fpr,
  keyIdHex,
  readUserPublicKey,
  describeKey,
  groupFpr,
} from './pgp';
import { normalizeFpr, normalizeWord, randomCode, randomInt, randomWords, sha256Hex } from './util';

export interface Ctx {
  store: Store;
  fpr: string;
  userKey: PublicKey;
  serverKey: PrivateKey;
  serverEmail: string;
}

type Body = Record<string, unknown>;

interface Grader {
  start?: (ctx: Ctx) => Promise<StartResult>;
  grade: (ctx: Ctx, body: Body) => Promise<GradeResult>;
}

const HOUR = 3600;
const DAY = 86400;
const PLAINTEXT_PREVIEW = 4000;

const fail = (headline: string, details: string[] = [], hint?: string): GradeResult => ({ ok: false, headline, details, hint });

async function requireChallenge(ctx: Ctx, exercise: string) {
  const ch = await ctx.store.getChallenge(ctx.fpr, exercise);
  if (!ch) throw new UserError('This exercise has not been started or the challenge expired.', 'Press "Start / new challenge" first.');
  return { ...ch, parsed: ch.data ? JSON.parse(ch.data) : {} };
}

async function readArmoredMessage(text: string) {
  if (/-----BEGIN PGP SIGNED MESSAGE-----/.test(text)) {
    throw new UserError('That is a clearsigned message, not an encrypted one.', 'Use --encrypt (and --armor).');
  }
  if (/-----BEGIN PGP PUBLIC KEY BLOCK-----/.test(text)) throw new UserError('That is a public key, not a message.');
  try {
    return await openpgp.readMessage({ armoredMessage: text });
  } catch (e) {
    throw new UserError(`Could not read that message: ${errMsg(e)}`, 'Paste the complete armored output including the BEGIN/END PGP MESSAGE lines. Did you use --armor?');
  }
}

function serverKeyIds(ctx: Ctx): Set<string> {
  return new Set([ctx.serverKey, ...ctx.serverKey.subkeys].map((k) => k.getKeyID().toHex().toUpperCase()));
}

/** Check a message is encrypted to the server, then decrypt it (verifying signatures against the user key). */
async function decryptForServer(ctx: Ctx, text: string) {
  const message = await readArmoredMessage(text);
  const recipients = message.getEncryptionKeyIDs().map(keyIdHex);
  if (recipients.length === 0) {
    throw new UserError(
      'That message is not encrypted (it has no recipients).',
      'It looks like a signed-only message. Add --encrypt --recipient ' + ctx.serverEmail,
    );
  }
  const ids = serverKeyIds(ctx);
  const hidden = recipients.includes('0000000000000000');
  if (!hidden && !recipients.some((r) => ids.has(r))) {
    throw new UserError(
      `This message is encrypted to key ID(s) ${recipients.join(', ')}, but not to the server.`,
      `Use --recipient ${ctx.serverEmail} (the server's encryption subkey is ${[...ids][1] ?? [...ids][0]}).`,
    );
  }
  try {
    const res = await openpgp.decrypt({ message, decryptionKeys: ctx.serverKey, verificationKeys: ctx.userKey, format: 'utf8' });
    return { ...res, recipients };
  } catch (e) {
    throw new UserError(`The server could not decrypt it: ${errMsg(e)}`);
  }
}

const preview = (s: string) => (s.length > PLAINTEXT_PREVIEW ? s.slice(0, PLAINTEXT_PREVIEW) + '\n…(truncated)' : s);

const includesPhrase = (text: string, phrase: string) =>
  text.toLowerCase().replace(/\s+/g, ' ').includes(phrase.toLowerCase());

const phraseStart = (id: string) => async (ctx: Ctx): Promise<StartResult> => {
  const phrase = randomWords(3);
  await ctx.store.setChallenge(ctx.fpr, id, null, { phrase }, DAY);
  return { prompt: `Include this phrase in your message: “${phrase}”`, phrase };
};

// ---------------------------------------------------------------------------------------------

const TAMPER_TEMPLATES: [string, string, string][] = [
  ['Please transfer 25 credits to account 1042.', '25 credits', '925 credits'],
  ['The team meeting has moved to Thursday at 10:00.', 'Thursday', 'Friday'],
  ['Release v2.4.1 is approved for deployment.', 'v2.4.1', 'v2.4.7'],
  ['Please rotate the API token for the build server.', 'rotate', 'publish'],
  ['The backup drive is stored in locker 12.', 'locker 12', 'locker 21'],
  ['Our office Wi-Fi password changed on Monday.', 'Monday', 'Sunday'],
];

export const GRADERS: Record<string, Grader> = {
  fingerprint: {
    async grade(ctx, body) {
      const given = normalizeFpr(String(body.answer ?? ''));
      const actual = fpr(ctx.serverKey);
      if (given.length === 0) throw new UserError('Please type the fingerprint.');
      if (given === actual) {
        return { ok: true, headline: 'Fingerprint matches!', details: [`Server fingerprint: ${groupFpr(actual)}`] };
      }
      if (given.length < 40 && actual.endsWith(given)) {
        return fail('That is only part of the fingerprint.', [], 'Type all 40 hex characters (spaces are fine). Short key IDs can be forged.');
      }
      return fail('That fingerprint does not match the server key.', [], 'Run gpg --fingerprint ' + ctx.serverEmail + ' and copy the line of hex under "pub".');
    },
  },

  encrypt: {
    async grade(ctx, body) {
      const text = assertInput(body.armored, 'encrypted message');
      const { data, signatures, recipients } = await decryptForServer(ctx, text);
      const plaintext = String(data);
      if (!plaintext.trim()) return fail('Decrypted fine, but the message was empty.');
      const details = [`Encrypted to key ID(s): ${recipients.join(', ')}`];
      const sigs = await checkSignatures(signatures, ctx.userKey);
      sigs.forEach((s) => details.push(describeSig(s)));
      if (!sigs.length) details.push('The message was not signed — the server cannot tell who wrote it (see the sign-and-encrypt exercise).');
      return { ok: true, headline: 'The server decrypted your message.', details, plaintext: preview(plaintext) };
    },
  },

  clearsign: {
    async grade(ctx, body) {
      const text = assertInput(body.armored, 'clearsigned message');
      const { parsed } = await requireChallenge(ctx, 'clearsign');
      if (/-----BEGIN PGP MESSAGE-----/.test(text)) {
        return fail('That is an opaque signed (or encrypted) message, not a clearsigned one.', [], 'Use gpg --clearsign (not --sign).');
      }
      let message;
      try {
        message = await openpgp.readCleartextMessage({ cleartextMessage: text });
      } catch (e) {
        throw new UserError(`Could not read that clearsigned message: ${errMsg(e)}`, 'Paste everything from -----BEGIN PGP SIGNED MESSAGE----- to -----END PGP SIGNATURE-----.');
      }
      const { signatures } = await openpgp.verify({ message, verificationKeys: ctx.userKey });
      const sigs = await checkSignatures(signatures, ctx.userKey);
      const details = sigs.map(describeSig);
      const content = message.getText();
      const good = sigs.some((s) => s.valid && s.byUser);
      if (!good) return fail('No valid signature from your key.', details, 'Sign with the key you uploaded (use --local-user <fingerprint> if you have several).');
      if (!includesPhrase(content, parsed.phrase)) {
        return fail('Signature is good, but the message does not contain the phrase.', details, `Include “${parsed.phrase}” in the signed text.`);
      }
      await ctx.store.deleteChallenge(ctx.fpr, 'clearsign');
      return { ok: true, headline: 'Valid clearsigned message from your key.', details, plaintext: preview(content) };
    },
    start: phraseStart('clearsign'),
  },

  detached: {
    async start(ctx) {
      const content =
        'PGPractice detached signature exercise\n' +
        `Key: ${ctx.fpr}\n` +
        `Nonce: ${randomCode(4)}\n` +
        `Issued: ${new Date().toISOString()}\n` +
        'Do not edit this file - sign it as-is.\n';
      await ctx.store.setChallenge(ctx.fpr, 'detached', null, { content }, DAY);
      return { file: { name: 'practice.txt', content } };
    },
    async grade(ctx, body) {
      const text = assertInput(body.armored, 'detached signature');
      const { parsed } = await requireChallenge(ctx, 'detached');
      if (/-----BEGIN PGP MESSAGE-----/.test(text)) {
        return fail('That is a signed message containing the file, not a detached signature.', [], 'Use gpg --armor --detach-sign practice.txt and paste practice.txt.asc.');
      }
      if (/-----BEGIN PGP SIGNED MESSAGE-----/.test(text)) {
        return fail('That is a clearsigned message, not a detached signature.', [], 'Use gpg --armor --detach-sign practice.txt.');
      }
      let signature;
      try {
        signature = await openpgp.readSignature({ armoredSignature: text });
      } catch (e) {
        throw new UserError(`Could not read that signature: ${errMsg(e)}`, 'Did you include --armor? Paste the whole .asc file.');
      }
      const textMode = signature.packets[0]?.signatureType === openpgp.enums.signature.text;
      const message = textMode
        ? await openpgp.createMessage({ text: parsed.content })
        : await openpgp.createMessage({ binary: new TextEncoder().encode(parsed.content) });
      const { signatures } = await openpgp.verify({ message, signature, verificationKeys: ctx.userKey });
      const sigs = await checkSignatures(signatures, ctx.userKey);
      const details = sigs.map(describeSig);
      details.push(`Signature mode: ${textMode ? 'text (--textmode)' : 'binary'}`);
      if (!sigs.some((s) => s.valid && s.byUser)) {
        return fail('The signature does not verify against practice.txt with your key.', details, 'Download a fresh practice.txt and sign it without opening or editing it. Make sure you sign with the key you uploaded.');
      }
      await ctx.store.deleteChallenge(ctx.fpr, 'detached');
      return { ok: true, headline: 'Valid detached signature over practice.txt.', details };
    },
  },

  'sign-encrypt': {
    start: phraseStart('sign-encrypt'),
    async grade(ctx, body) {
      const text = assertInput(body.armored, 'signed and encrypted message');
      const { parsed } = await requireChallenge(ctx, 'sign-encrypt');
      const { data, signatures, recipients } = await decryptForServer(ctx, text);
      const plaintext = String(data);
      const sigs = await checkSignatures(signatures, ctx.userKey);
      const details = [`Encrypted to key ID(s): ${recipients.join(', ')}`, ...sigs.map(describeSig)];
      if (!sigs.length) return fail('Encrypted correctly, but not signed.', details, 'Add --sign to the gpg command.');
      if (!sigs.some((s) => s.valid && s.byUser)) return fail('The signature is not a valid signature from your key.', details);
      if (!includesPhrase(plaintext, parsed.phrase)) {
        return { ...fail('Signed and encrypted correctly, but the phrase is missing.', details, `Include “${parsed.phrase}”.`), plaintext: preview(plaintext) };
      }
      await ctx.store.deleteChallenge(ctx.fpr, 'sign-encrypt');
      return { ok: true, headline: 'Decrypted and verified: confidential and authenticated.', details, plaintext: preview(plaintext) };
    },
  },

  'read-reply': {
    async start(ctx) {
      const word = `${randomWords(1)}-${10 + randomInt(90)}`;
      await ctx.store.setChallenge(ctx.fpr, 'read-reply', await sha256Hex(normalizeWord(word)), {}, DAY);
      const text =
        'Hello from PGPractice!\n\n' +
        'If you can read this, you decrypted the message with your private key.\n' +
        'Before trusting it, check that GnuPG reported a *Good signature* from\n' +
        `PGPractice <${ctx.serverEmail}>.\n\n` +
        `The secret word is: ${word}\n`;
      return { blocks: [{ name: 'reply.asc', content: await encryptAndSign(text, ctx.userKey, ctx.serverKey) }] };
    },
    async grade(ctx, body) {
      const ch = await requireChallenge(ctx, 'read-reply');
      const answer = normalizeWord(String(body.answer ?? ''));
      if (!answer) throw new UserError('Please type the secret word.');
      if ((await sha256Hex(answer)) !== ch.secret_hash) return fail('That is not the secret word.', [], 'Type the word exactly as shown after "The secret word is:".');
      await ctx.store.deleteChallenge(ctx.fpr, 'read-reply');
      return { ok: true, headline: 'Correct! You decrypted the server’s reply.', details: ['Remember: decrypting proves the message was for you; the signature proves who sent it.'] };
    },
  },

  tamper: {
    async start(ctx) {
      // Pick 4 distinct templates; tamper with 1–3 of them.
      const pool = [...TAMPER_TEMPLATES];
      const chosen = Array.from({ length: 4 }, () => pool.splice(randomInt(pool.length), 1)[0]);
      const badCount = 1 + randomInt(3);
      const order = [0, 1, 2, 3].sort(() => randomInt(3) - 1);
      const bad = order.slice(0, badCount).sort();
      const blocks = [];
      for (let i = 0; i < chosen.length; i++) {
        const [text, from, to] = chosen[i];
        const body = `${text}\nRef: ${randomCode(1, 6)}\n`;
        let armored = await clearsign(body, ctx.serverKey);
        if (bad.includes(i)) armored = armored.replace(from, to);
        blocks.push({ name: `m${i + 1}.asc`, content: armored });
      }
      await ctx.store.setChallenge(ctx.fpr, 'tamper', null, { bad }, DAY);
      return { blocks, choices: blocks.map((b, i) => `Message ${i + 1} (${b.name})`) };
    },
    async grade(ctx, body) {
      const { parsed } = await requireChallenge(ctx, 'tamper');
      const picked = Array.isArray(body.choices) ? body.choices.map(Number).filter((n) => n >= 0 && n < 4) : [];
      const bad: number[] = parsed.bad;
      const correct = [0, 1, 2, 3].filter((i) => picked.includes(i) === bad.includes(i)).length;
      if (correct === 4) {
        await ctx.store.deleteChallenge(ctx.fpr, 'tamper');
        return { ok: true, headline: 'All four classified correctly!', details: [`Tampered: ${bad.map((i) => `m${i + 1}`).join(', ')}`] };
      }
      return fail(`${correct} of 4 messages classified correctly.`, [], 'Run gpg --verify on each file and look for “BAD signature” vs “Good signature”.');
    },
  },

  'key-update': {
    async grade(ctx, body) {
      const text = assertInput(body.armored, 'updated public key');
      const newKey = await readUserPublicKey(text);
      if (fpr(newKey) !== ctx.fpr) {
        return fail('That is a different key.', [`Uploaded: ${groupFpr(fpr(newKey))}`, `Expected: ${groupFpr(ctx.fpr)}`], 'Update the same key you signed in with.');
      }
      const old = ctx.userKey;
      const details: string[] = [];
      const oldSubs = new Set(old.subkeys.map((k) => k.getFingerprint()));
      for (const sk of newKey.subkeys) {
        if (!oldSubs.has(sk.getFingerprint())) {
          const info = sk.getAlgorithmInfo() as { algorithm: string; bits?: number };
          details.push(`New subkey ${keyIdHex(sk.getKeyID())} (${info.algorithm}${info.bits ? '-' + info.bits : ''})`);
        }
      }
      const oldUids = new Set(old.getUserIDs());
      for (const uid of newKey.getUserIDs()) if (!oldUids.has(uid)) details.push(`New user ID: ${uid}`);
      const fmt = (d: Date | number | null) => (d instanceof Date ? d.toISOString().slice(0, 10) : d === Infinity ? 'never' : 'unknown');
      const oldExp = await old.getExpirationTime().catch(() => null);
      const newExp = await newKey.getExpirationTime().catch(() => null);
      if (fmt(oldExp) !== fmt(newExp)) details.push(`Expiry changed: ${fmt(oldExp)} → ${fmt(newExp)}`);
      for (const sk of newKey.subkeys) {
        const before = old.subkeys.find((o) => o.getFingerprint() === sk.getFingerprint());
        if (!before) continue;
        const a = fmt(await before.getExpirationTime().catch(() => null));
        const b = fmt(await sk.getExpirationTime().catch(() => null));
        if (a !== b) details.push(`Subkey ${keyIdHex(sk.getKeyID())} expiry: ${a} → ${b}`);
      }
      if (!details.length) {
        return fail('No changes detected compared with the key you uploaded earlier.', [], 'Change the expiry, add a subkey or add a user ID, then export again.');
      }
      const d = await describeKey(newKey);
      await ctx.store.updateKeyMaterial(ctx.fpr, newKey.armor(), d.uid, d.algo);
      details.push('The server now uses your updated key.');
      return { ok: true, headline: 'Key update received.', details };
    },
  },

  revoke: {
    async grade(ctx, body) {
      const text = assertInput(body.armored, 'revocation certificate');
      let revoked;
      try {
        revoked = (await openpgp.revokeKey({ key: ctx.userKey, revocationCertificate: text, format: 'object' })).publicKey;
      } catch (e) {
        const msg = errMsg(e);
        const hint = /does not match/.test(msg)
          ? 'That certificate is for a different key.'
          : 'Generate it with gpg --output revoke.asc --gen-revoke <your fingerprint> and paste the whole file.';
        return fail(`Not a valid revocation certificate for your key: ${msg}`, [], hint);
      }
      const sig = revoked.revocationSignatures[revoked.revocationSignatures.length - 1];
      const reasons: Record<number, string> = { 0: 'no reason specified', 1: 'key superseded', 2: 'key compromised', 3: 'key no longer used' };
      const details = [
        `Reason: ${reasons[sig.reasonForRevocationFlag ?? 0] ?? `code ${sig.reasonForRevocationFlag}`}`,
        sig.reasonForRevocationString ? `Comment: ${sig.reasonForRevocationString}` : '',
        `Created: ${sig.created?.toISOString() ?? 'unknown'}`,
        'The server did NOT apply it — your key is still valid here. Keep the certificate offline.',
      ].filter(Boolean);
      return { ok: true, headline: 'Valid revocation certificate for your key.', details };
    },
  },

  certify: {
    async grade(ctx, body) {
      const text = assertInput(body.armored, "server's key with your certification");
      let key;
      try {
        key = await openpgp.readKey({ armoredKey: text });
      } catch (e) {
        throw new UserError(`Could not parse that key: ${errMsg(e)}`);
      }
      if (fpr(key) !== fpr(ctx.serverKey)) {
        return fail('That is not the PGPractice server key.', [`Got ${groupFpr(fpr(key))}`], `Export with gpg --armor --export ${fpr(ctx.serverKey)}`);
      }
      const myId = ctx.userKey.getKeyID().toHex().toUpperCase();
      const details: string[] = [];
      let found = false;
      for (const user of key.users) {
        if (!user.userID) continue;
        const results = await user.verifyAllCertifications([ctx.userKey]);
        for (const r of results) {
          if (keyIdHex(r.keyID) !== myId) continue;
          found = true;
          details.push(`${r.valid ? 'Valid' : 'Invalid'} certification by your key on “${user.userID.userID}”.`);
          if (r.valid) {
            await ctx.store.touch(ctx.fpr);
            return { ok: true, headline: 'You certified the server key.', details: [...details, 'In the Web of Trust, others who trust you can now rely on your check of this key.'] };
          }
        }
      }
      return fail(
        found ? 'Your certification did not verify.' : 'No certification from your key was found.',
        details,
        'Use gpg --quick-sign-key (not --lsign/--quick-lsign, whose signatures are not exported), then gpg --armor --export the SERVER key.',
      );
    },
  },
};

export async function makeLoginChallenge(store: Store, userKey: PublicKey, serverKey: PrivateKey, origin: string) {
  const code = randomCode();
  const f = fpr(userKey);
  await store.setChallenge(f, 'decrypt', await sha256Hex(code.replace(/-/g, '')), null, HOUR);
  const text =
    'Welcome to PGPractice!\n\n' +
    'You decrypted this message with your private key, which proves you own\n' +
    `the key ${groupFpr(f)}.\n\n` +
    'Your verification code is:\n\n' +
    `    ${code}\n\n` +
    `Paste it at ${origin} within one hour.\n`;
  return encryptAndSign(text, userKey, serverKey);
}
