// Exercise catalogue shared by the worker (grading) and the web UI (lessons).
// Instruction text is static, trusted content authored here; it may contain simple inline HTML.
// Placeholders: {SERVER_EMAIL}, {SERVER_FPR}, {MY_FPR}, {ORIGIN}, {PHRASE}

export type InputKind = 'none' | 'armored' | 'text' | 'choice';

export interface Step {
  text: string;
  cmd?: string;
}

export interface ExerciseMeta {
  id: string;
  title: string;
  summary: string;
  /** Exercise needs a server-generated challenge first (GET /start). */
  hasStart: boolean;
  input: InputKind;
  inputLabel?: string;
  steps: Step[];
  pitfalls?: string[];
}

export const EXERCISES: ExerciseMeta[] = [
  {
    id: 'upload',
    title: 'Create & upload your public key',
    summary: 'Generate a key pair with GnuPG and share only the public half.',
    hasStart: false,
    input: 'none',
    steps: [
      { text: 'Generate a new key pair. Accept the default algorithm (ECC / Curve 25519) and choose an expiry such as <code>1y</code>.', cmd: 'gpg --full-generate-key' },
      { text: 'List your keys and note the 40-character fingerprint.', cmd: 'gpg --list-keys --keyid-format long --fingerprint' },
      { text: 'Export the <strong>public</strong> key in ASCII armor and paste it on the home page.', cmd: 'gpg --armor --export you@example.com' },
    ],
    pitfalls: [
      'Never paste anything that says <code>PRIVATE KEY BLOCK</code> — that is your secret key.',
      'Forgetting <code>--armor</code> produces binary output that cannot be pasted.',
    ],
  },
  {
    id: 'fingerprint',
    title: "Import & verify the server's key",
    summary: "Import PGPractice's public key and confirm its fingerprint out of band.",
    hasStart: false,
    input: 'text',
    inputLabel: 'Fingerprint you see',
    steps: [
      { text: 'Fetch the key via Web Key Directory (WKD)…', cmd: 'gpg --auto-key-locate clear,wkd,nodefault --locate-keys {SERVER_EMAIL}' },
      { text: '…or download it directly and import it.', cmd: 'curl -s {ORIGIN}/api/server-key.asc | gpg --import' },
      { text: 'Show its fingerprint and type it below. Compare it with the one shown in the page footer — in real life you would compare it over a separate, trusted channel.', cmd: 'gpg --fingerprint {SERVER_EMAIL}' },
    ],
    pitfalls: ['Short key IDs (8 hex chars) are easy to forge; always compare full fingerprints.'],
  },
  {
    id: 'decrypt',
    title: 'Decrypt a challenge',
    summary: 'Prove you own your key by decrypting a message encrypted to it.',
    hasStart: false,
    input: 'none',
    steps: [
      { text: 'After uploading your key the home page shows an encrypted challenge. Save it to <code>challenge.asc</code> and decrypt it.', cmd: 'gpg --decrypt challenge.asc' },
      { text: 'GnuPG also reports a <em>Good signature</em> from PGPractice — the challenge is signed as well as encrypted.' },
      { text: 'Paste the verification code back on the home page. This completes the exercise and signs you in.' },
    ],
  },
  {
    id: 'encrypt',
    title: 'Encrypt a message to the server',
    summary: 'Encrypt any message so only PGPractice can read it.',
    hasStart: false,
    input: 'armored',
    inputLabel: 'Encrypted message (-----BEGIN PGP MESSAGE-----)',
    steps: [
      { text: 'Write a short message and encrypt it to the server key.', cmd: 'echo "Hello PGPractice" | gpg --armor --encrypt --recipient {SERVER_EMAIL}' },
      { text: 'Paste the armored output below. The server will decrypt it and show what it read.' },
    ],
    pitfalls: [
      'If GnuPG asks whether to use a key "anyway", the server key is not yet certified/trusted — fine for practice, but read exercise 12.',
      'Encrypting to yourself only (wrong <code>--recipient</code>) means the server cannot read it.',
    ],
  },
  {
    id: 'clearsign',
    title: 'Clearsign a message',
    summary: 'Create a human-readable signed message that includes a phrase from the server.',
    hasStart: true,
    input: 'armored',
    inputLabel: 'Clearsigned message (-----BEGIN PGP SIGNED MESSAGE-----)',
    steps: [
      { text: 'Write a message containing the phrase shown below into <code>note.txt</code>, then clearsign it.', cmd: 'echo "My phrase: {PHRASE}" > note.txt && gpg --clearsign note.txt' },
      { text: 'Paste the contents of <code>note.txt.asc</code> below.', cmd: 'cat note.txt.asc' },
    ],
    pitfalls: ['<code>gpg --sign</code> (without "clear") produces an opaque binary-style signed message instead.'],
  },
  {
    id: 'detached',
    title: 'Create a detached signature',
    summary: 'Sign a file without modifying it, producing a separate .asc signature.',
    hasStart: true,
    input: 'armored',
    inputLabel: 'Detached signature (-----BEGIN PGP SIGNATURE-----)',
    steps: [
      { text: 'Download <code>practice.txt</code> with the button below. Do not edit it — even one changed byte breaks the signature.' },
      { text: 'Create an armored detached signature.', cmd: 'gpg --armor --detach-sign practice.txt' },
      { text: 'Optionally verify it yourself, then paste <code>practice.txt.asc</code> below.', cmd: 'gpg --verify practice.txt.asc practice.txt' },
    ],
  },
  {
    id: 'sign-encrypt',
    title: 'Sign and encrypt',
    summary: 'Send a message that is both confidential and authenticated.',
    hasStart: true,
    input: 'armored',
    inputLabel: 'Signed + encrypted message (-----BEGIN PGP MESSAGE-----)',
    steps: [
      { text: 'Sign with your key and encrypt to the server in one step. Include the phrase shown below.', cmd: 'echo "My phrase: {PHRASE}" | gpg --armor --sign --encrypt --recipient {SERVER_EMAIL}' },
      { text: 'Paste the output below.' },
    ],
    pitfalls: ['Encrypt-only messages are not authenticated: anyone with the server public key could have written them.'],
  },
  {
    id: 'read-reply',
    title: 'Read a signed & encrypted reply',
    summary: 'Decrypt a message from the server and check who signed it.',
    hasStart: true,
    input: 'text',
    inputLabel: 'Secret word',
    steps: [
      { text: 'Save the message below as <code>reply.asc</code> and decrypt it. Check that GnuPG reports a <em>Good signature</em> from PGPractice.', cmd: 'gpg --decrypt reply.asc' },
      { text: 'Type the secret word from the message below.' },
    ],
  },
  {
    id: 'tamper',
    title: 'Spot the tampered messages',
    summary: 'Some of these signed messages were altered after signing. Find them.',
    hasStart: true,
    input: 'choice',
    inputLabel: 'Which messages have a BAD signature?',
    steps: [
      { text: 'Save each message to a file (e.g. <code>m1.asc</code> … <code>m4.asc</code>) and verify it.', cmd: 'for f in m*.asc; do echo "== $f"; gpg --verify "$f"; done' },
      { text: 'Tick every message for which GnuPG reports <strong>BAD signature</strong>.' },
    ],
    pitfalls: ['A message that merely <em>looks</em> plausible is not evidence; only the signature check is.'],
  },
  {
    id: 'key-update',
    title: 'Update your key',
    summary: 'Change your key (expiry, subkey or user ID) and publish the update.',
    hasStart: false,
    input: 'armored',
    inputLabel: 'Updated public key (-----BEGIN PGP PUBLIC KEY BLOCK-----)',
    steps: [
      { text: 'Make at least one change. For example extend the expiry…', cmd: 'gpg --quick-set-expire {MY_FPR} 2y' },
      { text: '…or add a new signing subkey…', cmd: 'gpg --quick-add-key {MY_FPR} ed25519 sign 1y' },
      { text: '…or add another user ID.', cmd: 'gpg --quick-add-uid {MY_FPR} "Your Name <other@example.com>"' },
      { text: 'Export the updated public key and paste it below.', cmd: 'gpg --armor --export {MY_FPR}' },
    ],
    pitfalls: ['Changes only reach others when you re-distribute the public key.'],
  },
  {
    id: 'revoke',
    title: 'Create a revocation certificate',
    summary: 'Prepare for disaster: generate (but do not import!) a revocation certificate.',
    hasStart: false,
    input: 'armored',
    inputLabel: 'Revocation certificate',
    steps: [
      { text: 'Generate a revocation certificate and store it somewhere safe and offline.', cmd: 'gpg --output revoke.asc --gen-revoke {MY_FPR}' },
      { text: 'GnuPG also made one automatically when you created the key.', cmd: 'ls ~/.gnupg/openpgp-revocs.d/' },
      { text: 'Paste <code>revoke.asc</code> below. The server checks it but does <strong>not</strong> apply it.' },
    ],
    pitfalls: [
      'Do <strong>not</strong> run <code>gpg --import revoke.asc</code> — that would revoke your key for real.',
      'Anyone who obtains this certificate can revoke your key; treat it like a secret.',
    ],
  },
  {
    id: 'certify',
    title: "Certify the server's key",
    summary: "Sign PGPractice's key to vouch for it, then send back your certification.",
    hasStart: false,
    input: 'armored',
    inputLabel: "Server's public key with your certification",
    steps: [
      { text: 'After verifying the fingerprint (exercise 2), certify the server key with an <em>exportable</em> signature.', cmd: 'gpg --quick-sign-key {SERVER_FPR}' },
      { text: 'Check your signature is attached.', cmd: 'gpg --check-signatures {SERVER_EMAIL}' },
      { text: 'Export the server key (now carrying your certification) and paste it below.', cmd: 'gpg --armor --export {SERVER_FPR}' },
    ],
    pitfalls: ['<code>--lsign-key</code> / <code>--quick-lsign-key</code> creates a local, non-exportable signature that is never exported.'],
  },
];

export const EXERCISE_IDS = EXERCISES.map((e) => e.id);

export function getExercise(id: string): ExerciseMeta | undefined {
  return EXERCISES.find((e) => e.id === id);
}

/** Result returned by every grader. */
export interface GradeResult {
  ok: boolean;
  headline: string;
  details: string[];
  /** Text decrypted by the server, shown once and never stored. */
  plaintext?: string;
  hint?: string;
}

export interface StartResult {
  /** Free text shown above the input (e.g. the phrase to include). */
  prompt?: string;
  /** Armored blocks to show/download. */
  blocks?: { name: string; content: string }[];
  /** A file to download verbatim. */
  file?: { name: string; content: string };
  /** Phrase to substitute for {PHRASE} in commands. */
  phrase?: string;
  /** For choice-type exercises. */
  choices?: string[];
}
