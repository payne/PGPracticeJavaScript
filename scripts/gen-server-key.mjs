// Generates the server's OpenPGP key (v4, Ed25519 primary + Cv25519 encryption subkey).
// Generated with OpenPGP.js (not gpg) so the key does not advertise LibrePGP OCB/AEAD,
// which means GnuPG will encrypt to it using SEIPDv1 (MDC) that OpenPGP.js can read.
//
// Output: secrets/server-private.asc, secrets/server-public.asc, secrets/server-revocation.asc
// Then:   npx wrangler secret put SERVER_PRIVATE_KEY < secrets/server-private.asc
import * as openpgp from 'openpgp';
import { mkdirSync, writeFileSync, existsSync } from 'node:fs';

const email = process.argv[2] || 'practice@pgpractice.appfarms.org';
const out = 'secrets';
if (existsSync(`${out}/server-private.asc`) && !process.argv.includes('--force')) {
  console.error(`${out}/server-private.asc exists; pass --force to overwrite`);
  process.exit(1);
}
mkdirSync(out, { recursive: true, mode: 0o700 });
const { privateKey, publicKey, revocationCertificate } = await openpgp.generateKey({
  type: 'ecc',
  curve: 'curve25519Legacy',
  userIDs: [{ name: 'PGPractice', email }],
  format: 'armored',
});
writeFileSync(`${out}/server-private.asc`, privateKey, { mode: 0o600 });
writeFileSync(`${out}/server-public.asc`, publicKey);
writeFileSync(`${out}/server-revocation.asc`, revocationCertificate, { mode: 0o600 });
const key = await openpgp.readKey({ armoredKey: publicKey });
console.log('Generated server key', key.getFingerprint().toUpperCase(), 'for', email);
