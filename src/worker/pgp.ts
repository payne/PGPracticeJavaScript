import * as openpgp from 'openpgp';
import type { PublicKey, PrivateKey, Key } from 'openpgp';

export const MAX_INPUT = 64 * 1024;

export class UserError extends Error {
  constructor(message: string, public hint?: string, public status = 400) {
    super(message);
  }
}

export function assertInput(text: unknown, what = 'input'): string {
  if (typeof text !== 'string' || !text.trim()) throw new UserError(`Please paste the ${what}.`);
  if (text.length > MAX_INPUT) throw new UserError(`The ${what} is too large (max 64 KB).`);
  if (/-----BEGIN PGP PRIVATE KEY BLOCK-----/.test(text)) {
    throw new UserError(
      'That is a PRIVATE key. Never share it!',
      'Export only the public key with: gpg --armor --export <your-email>. If you pasted a real secret key anywhere, consider it compromised.',
    );
  }
  // GnuPG prefixes the BEGIN line of auto-generated revocation certificates with ':' to prevent accidental import.
  return text.replace(/^:(-----BEGIN PGP )/m, '$1').trim() + '\n';
}

export const fpr = (k: Key) => k.getFingerprint().toUpperCase();
export const keyIdHex = (id: { toHex(): string }) => id.toHex().toUpperCase();
export const groupFpr = (f: string) => f.replace(/(.{4})/g, '$1 ').trim();

let serverKeyCache: { armored: string; priv: Promise<PrivateKey> } | undefined;

export function serverPrivateKey(armored: string | undefined): Promise<PrivateKey> {
  if (!armored) throw new UserError('Server key is not configured.', undefined, 500);
  if (serverKeyCache?.armored !== armored) {
    serverKeyCache = { armored, priv: openpgp.readPrivateKey({ armoredKey: armored }) };
  }
  return serverKeyCache.priv;
}

export async function describeKey(key: PublicKey) {
  const info = key.getAlgorithmInfo() as { algorithm: string; bits?: number; curve?: string };
  const algo = friendlyAlgo(info);
  let uid = '';
  try {
    const primary = await key.getPrimaryUser();
    uid = primary.user.userID?.userID ?? '';
  } catch {
    uid = key.users.find((u) => u.userID)?.userID?.userID ?? '';
  }
  const exp = await key.getExpirationTime().catch(() => null);
  return {
    fingerprint: fpr(key),
    algo,
    uid,
    expires: exp instanceof Date ? exp.toISOString() : exp === Infinity ? 'never' : null,
    subkeys: key.subkeys.length,
  };
}

export function friendlyAlgo(info: { algorithm: string; bits?: number; curve?: string }): string {
  if (info.algorithm.startsWith('rsa')) return `RSA-${info.bits ?? '?'}`;
  const curves: Record<string, string> = {
    ed25519Legacy: 'Ed25519', curve25519Legacy: 'Curve25519', nistP256: 'NIST P-256', nistP384: 'NIST P-384',
    nistP521: 'NIST P-521', brainpoolP256r1: 'Brainpool P-256', brainpoolP384r1: 'Brainpool P-384', brainpoolP512r1: 'Brainpool P-512',
  };
  const names: Record<string, string> = { ed25519: 'Ed25519', ed448: 'Ed448', x25519: 'X25519', x448: 'X448', ecdsa: 'ECDSA', eddsaLegacy: 'EdDSA', ecdh: 'ECDH', dsa: 'DSA' };
  if (info.curve && info.algorithm === 'eddsaLegacy') return curves[info.curve] ?? info.curve;
  const base = names[info.algorithm] ?? info.algorithm;
  return info.curve ? `${base} (${curves[info.curve] ?? info.curve})` : base;
}

/** Parse and validate a user's public key for use with the exercises. */
export async function readUserPublicKey(armored: string): Promise<PublicKey> {
  let key: Key;
  try {
    key = await openpgp.readKey({ armoredKey: armored });
  } catch (e) {
    throw new UserError(`Could not parse that key: ${errMsg(e)}`, 'Paste the full output of gpg --armor --export <your-email>, including the BEGIN/END lines.');
  }
  if (key.isPrivate()) throw new UserError('That is a PRIVATE key. Never share it!');
  const pub = key as PublicKey;
  try {
    await pub.verifyPrimaryKey();
  } catch (e) {
    throw new UserError(`Your key is not usable: ${errMsg(e)}`, 'Expired or revoked keys cannot be used. Extend the expiry (gpg --quick-set-expire) or create a new key.');
  }
  const info = pub.getAlgorithmInfo() as { algorithm: string; bits?: number };
  if (info.algorithm.startsWith('rsa') && (info.bits ?? 0) < 2048) {
    throw new UserError(`RSA-${info.bits} is too weak.`, 'Create a key with the default algorithm (Curve 25519) or RSA of at least 3072 bits.');
  }
  try {
    await pub.getEncryptionKey();
  } catch {
    throw new UserError('Your key has no usable encryption subkey.', 'Add one with: gpg --quick-add-key <fingerprint> cv25519 encr 1y');
  }
  return pub;
}

export async function encryptAndSign(text: string, to: PublicKey, signer: PrivateKey): Promise<string> {
  const message = await openpgp.createMessage({ text });
  return (await openpgp.encrypt({ message, encryptionKeys: to, signingKeys: signer, format: 'armored' })) as string;
}

export async function clearsign(text: string, signer: PrivateKey): Promise<string> {
  const message = await openpgp.createCleartextMessage({ text });
  return openpgp.sign({ message, signingKeys: signer, format: 'armored' });
}

export function errMsg(e: unknown): string {
  const m = e instanceof Error ? e.message : String(e);
  // OpenPGP.js prefixes many messages with "Error decrypting message: " etc.; keep them, trim noise.
  return m.replace(/\s+/g, ' ').slice(0, 300);
}

export interface SigReport {
  valid: boolean;
  keyID: string;
  byUser: boolean;
  created?: string;
  error?: string;
}

/** Evaluate the signatures returned by openpgp.verify/decrypt against the user's key. */
export async function checkSignatures(
  sigs: { keyID: { toHex(): string }; verified: Promise<true>; signature: Promise<openpgp.Signature> }[],
  userKey: PublicKey,
): Promise<SigReport[]> {
  const userIds = new Set([userKey, ...userKey.subkeys].map((k) => k.getKeyID().toHex().toUpperCase()));
  const out: SigReport[] = [];
  for (const s of sigs) {
    const keyID = keyIdHex(s.keyID);
    const byUser = userIds.has(keyID);
    let created: string | undefined;
    try {
      const sig = await s.signature;
      const c = sig.packets[0]?.created;
      created = c ? c.toISOString() : undefined;
    } catch {
      /* ignore */
    }
    try {
      await s.verified;
      out.push({ valid: true, keyID, byUser, created });
    } catch (e) {
      out.push({ valid: false, keyID, byUser, created, error: errMsg(e) });
    }
  }
  return out;
}

export function describeSig(r: SigReport): string {
  const who = r.byUser ? 'your key' : 'an unknown key';
  if (r.valid) return `Good signature from ${who} (key ID ${r.keyID})${r.created ? `, made ${r.created}` : ''}.`;
  return `Signature by ${who} (key ID ${r.keyID}) did not verify: ${r.error}`;
}

/** WKD: z-base-32 encoded SHA-1 of the lowercased local part. */
export async function wkdHash(localPart: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-1', new TextEncoder().encode(localPart.toLowerCase())));
  const alphabet = 'ybndrfg8ejkmcpqxot1uwisza345h769';
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of digest) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}

export { openpgp };
