// A tiny, dependency-free OpenPGP packet dumper (think `gpg --list-packets` / pgpdump lite).
// Runs entirely in the browser; nothing is sent to the server.

export interface PacketInfo {
  depth: number;
  tag: number;
  name: string;
  length: number;
  fields: [string, string][];
  warning?: string;
}

const TAGS: Record<number, string> = {
  1: 'Public-Key Encrypted Session Key',
  2: 'Signature',
  3: 'Symmetric-Key Encrypted Session Key',
  4: 'One-Pass Signature',
  5: 'Secret Key',
  6: 'Public Key',
  7: 'Secret Subkey',
  8: 'Compressed Data',
  9: 'Symmetrically Encrypted Data (no integrity!)',
  10: 'Marker',
  11: 'Literal Data',
  12: 'Trust',
  13: 'User ID',
  14: 'Public Subkey',
  17: 'User Attribute (photo)',
  18: 'Sym. Encrypted Integrity Protected Data',
  19: 'Modification Detection Code',
  20: 'AEAD Encrypted Data (LibrePGP)',
  21: 'Padding',
};

const PK_ALGOS: Record<number, string> = {
  1: 'RSA', 2: 'RSA (encrypt only)', 3: 'RSA (sign only)', 16: 'ElGamal', 17: 'DSA', 18: 'ECDH', 19: 'ECDSA',
  22: 'EdDSA (legacy)', 25: 'X25519', 26: 'X448', 27: 'Ed25519', 28: 'Ed448',
};
const HASH_ALGOS: Record<number, string> = { 1: 'MD5', 2: 'SHA1', 3: 'RIPEMD160', 8: 'SHA256', 9: 'SHA384', 10: 'SHA512', 11: 'SHA224', 12: 'SHA3-256', 14: 'SHA3-512' };
const SYM_ALGOS: Record<number, string> = { 7: 'AES-128', 8: 'AES-192', 9: 'AES-256', 2: '3DES', 3: 'CAST5', 10: 'Twofish', 11: 'Camellia-128', 13: 'Camellia-256' };
const COMP_ALGOS: Record<number, string> = { 0: 'Uncompressed', 1: 'ZIP', 2: 'ZLIB', 3: 'BZip2' };
const SIG_TYPES: Record<number, string> = {
  0x00: 'Binary document', 0x01: 'Canonical text document', 0x02: 'Standalone',
  0x10: 'Generic certification', 0x11: 'Persona certification', 0x12: 'Casual certification', 0x13: 'Positive certification',
  0x18: 'Subkey binding', 0x19: 'Primary key binding', 0x1f: 'Direct key', 0x20: 'Key revocation',
  0x28: 'Subkey revocation', 0x30: 'Certification revocation', 0x40: 'Timestamp', 0x50: 'Third-party confirmation',
};
const CURVES: Record<string, string> = {
  '2b06010401da470f01': 'Ed25519 (legacy)', '2b060104019755010501': 'Curve25519 (legacy)',
  '2a8648ce3d030107': 'NIST P-256', '2b81040022': 'NIST P-384', '2b81040023': 'NIST P-521',
  '2b2403030208010107': 'brainpoolP256r1', '2b240303020801010d': 'brainpoolP512r1',
};
const REVOCATION_REASONS: Record<number, string> = { 0: 'No reason', 1: 'Superseded', 2: 'Compromised', 3: 'Retired', 32: 'User ID no longer valid' };

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const name = (map: Record<number, string>, v: number) => `${map[v] ?? 'unknown'} (${v})`;

const u32 = (b: Uint8Array, o: number) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
const time = (b: Uint8Array, o: number) => new Date(u32(b, o) * 1000).toISOString().replace('.000Z', 'Z');

/** Extract binary data from an ASCII-armored block (the first block, or the signature of a cleartext message). */
export function dearmor(text: string): { type: string; data: Uint8Array; cleartext?: string } {
  const lines = text.replace(/\r/g, '').split('\n').map((l) => l.replace(/^:(-----BEGIN)/, '$1'));
  let i = lines.findIndex((l) => /^-----BEGIN PGP [A-Z ,0-9/]+-----$/.test(l.trim()));
  if (i < 0) throw new Error('No “-----BEGIN PGP …-----” line found.');
  let type = lines[i].trim().slice(15, -5);
  let cleartext: string | undefined;
  if (type === 'SIGNED MESSAGE') {
    // Skip Hash: headers and cleartext up to the signature armor.
    const sigStart = lines.findIndex((l, idx) => idx > i && l.trim() === '-----BEGIN PGP SIGNATURE-----');
    if (sigStart < 0) throw new Error('Clearsigned message without a signature block.');
    let bodyStart = i + 1;
    while (bodyStart < sigStart && lines[bodyStart].trim() !== '') bodyStart++;
    cleartext = lines.slice(bodyStart + 1, sigStart).map((l) => l.replace(/^- /, '')).join('\n');
    i = sigStart;
    type = 'SIGNATURE (of a cleartext message)';
  }
  i++;
  while (i < lines.length && lines[i].trim() !== '') {
    if (!/^[A-Za-z-]+: /.test(lines[i])) break; // tolerate missing blank line
    i++;
  }
  let b64 = '';
  for (; i < lines.length; i++) {
    const l = lines[i].trim();
    if (l.startsWith('-----END') || (l.startsWith('=') && l.length === 5)) break;
    b64 += l;
  }
  const bin = atob(b64.replace(/[^A-Za-z0-9+/=]/g, ''));
  return { type, data: Uint8Array.from(bin, (c) => c.charCodeAt(0)), cleartext };
}

async function inflate(data: Uint8Array, algo: number): Promise<Uint8Array | null> {
  if ((algo !== 1 && algo !== 2) || typeof DecompressionStream === 'undefined') return null;
  const ds = new DecompressionStream(algo === 1 ? 'deflate-raw' : 'deflate');
  const stream = new Blob([data as Uint8Array<ArrayBuffer>]).stream().pipeThrough(ds);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

function parseSubpackets(b: Uint8Array, fields: [string, string][], label: string) {
  let o = 0;
  while (o < b.length) {
    let len = b[o++];
    if (len >= 192 && len < 255) len = ((len - 192) << 8) + b[o++] + 192;
    else if (len === 255) { len = u32(b, o); o += 4; }
    const type = b[o] & 0x7f;
    const d = b.subarray(o + 1, o + len);
    o += len;
    switch (type) {
      case 2: fields.push([`${label} created`, time(d, 0)]); break;
      case 3: fields.push([`${label} sig expires after`, `${u32(d, 0)} s`]); break;
      case 9: fields.push([`${label} key expires after`, `${Math.round(u32(d, 0) / 86400)} days`]); break;
      case 16: fields.push([`${label} issuer key ID`, hex(d).toUpperCase()]); break;
      case 33: fields.push([`${label} issuer fingerprint`, hex(d.subarray(1)).toUpperCase()]); break;
      case 27: fields.push([`${label} key flags`, keyFlags(d[0])]); break;
      case 29: fields.push([`${label} revocation reason`, `${REVOCATION_REASONS[d[0]] ?? d[0]}${d.length > 1 ? `: ${new TextDecoder().decode(d.subarray(1))}` : ''}`]); break;
      case 28: fields.push([`${label} signer user ID`, new TextDecoder().decode(d)]); break;
      case 4: fields.push([`${label} exportable`, d[0] ? 'yes' : 'NO (local signature)']); break;
    }
  }
}

function keyFlags(f: number): string {
  const out = [];
  if (f & 1) out.push('certify');
  if (f & 2) out.push('sign');
  if (f & 4) out.push('encrypt comms');
  if (f & 8) out.push('encrypt storage');
  if (f & 0x20) out.push('authenticate');
  return out.join(', ') || 'none';
}

function keyFields(d: Uint8Array, fields: [string, string][]) {
  const v = d[0];
  fields.push(['Version', String(v)]);
  if (v !== 4 && v !== 6) return;
  fields.push(['Created', time(d, 1)]);
  const algo = d[5];
  fields.push(['Algorithm', name(PK_ALGOS, algo)]);
  let o = v === 6 ? 10 : 6;
  if (algo === 1 || algo === 2 || algo === 3) {
    fields.push(['RSA modulus', `${(d[o] << 8) | d[o + 1]} bits`]);
  } else if ([18, 19, 22].includes(algo)) {
    const oidLen = d[o];
    const oid = hex(d.subarray(o + 1, o + 1 + oidLen));
    fields.push(['Curve', CURVES[oid] ?? `OID ${oid}`]);
  }
}

async function walk(data: Uint8Array, depth: number, out: PacketInfo[]) {
  let o = 0;
  while (o < data.length && out.length < 200) {
    const h = data[o++];
    if (!(h & 0x80)) throw new Error(`Invalid packet header at byte ${o - 1}.`);
    let tag: number;
    let body: Uint8Array;
    if (h & 0x40) {
      tag = h & 0x3f;
      const chunks: Uint8Array[] = [];
      for (;;) {
        const l1 = data[o++];
        let len: number;
        let partial = false;
        if (l1 < 192) len = l1;
        else if (l1 < 224) len = ((l1 - 192) << 8) + data[o++] + 192;
        else if (l1 === 255) { len = u32(data, o); o += 4; }
        else { len = 1 << (l1 & 0x1f); partial = true; }
        chunks.push(data.subarray(o, o + len));
        o += len;
        if (!partial) break;
      }
      body = chunks.length === 1 ? chunks[0] : concat(chunks);
    } else {
      tag = (h >> 2) & 0x0f;
      const lt = h & 3;
      let len: number;
      if (lt === 0) len = data[o++];
      else if (lt === 1) { len = (data[o] << 8) | data[o + 1]; o += 2; }
      else if (lt === 2) { len = u32(data, o); o += 4; }
      else len = data.length - o;
      body = data.subarray(o, o + len);
      o += len;
    }
    const p: PacketInfo = { depth, tag, name: TAGS[tag] ?? `Unknown (${tag})`, length: body.length, fields: [] };
    out.push(p);
    await describe(p, body, depth, out);
  }
}

function concat(chunks: Uint8Array[]) {
  const r = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let o = 0;
  for (const c of chunks) { r.set(c, o); o += c.length; }
  return r;
}

async function describe(p: PacketInfo, d: Uint8Array, depth: number, out: PacketInfo[]) {
  const f = p.fields;
  switch (p.tag) {
    case 1:
      f.push(['Version', String(d[0])]);
      if (d[0] === 3) {
        const id = hex(d.subarray(1, 9)).toUpperCase();
        f.push(['Recipient key ID', id === '0000000000000000' ? 'hidden (wildcard)' : id]);
        f.push(['Algorithm', name(PK_ALGOS, d[9])]);
      }
      break;
    case 2: {
      f.push(['Version', String(d[0])]);
      if (d[0] === 4 || d[0] === 6) {
        f.push(['Signature type', name(SIG_TYPES, d[1])]);
        f.push(['Public-key algorithm', name(PK_ALGOS, d[2])]);
        f.push(['Hash algorithm', name(HASH_ALGOS, d[3])]);
        const wide = d[0] === 6;
        let o = 4;
        const hl = wide ? u32(d, o) : (d[o] << 8) | d[o + 1];
        o += wide ? 4 : 2;
        parseSubpackets(d.subarray(o, o + hl), f, 'Hashed:');
        o += hl;
        const ul = wide ? u32(d, o) : (d[o] << 8) | d[o + 1];
        o += wide ? 4 : 2;
        parseSubpackets(d.subarray(o, o + ul), f, 'Unhashed:');
      }
      break;
    }
    case 3:
      f.push(['Version', String(d[0])]);
      f.push(['Cipher', name(SYM_ALGOS, d[1])]);
      break;
    case 4:
      f.push(['Signature type', name(SIG_TYPES, d[1])]);
      f.push(['Hash algorithm', name(HASH_ALGOS, d[2])]);
      f.push(['Public-key algorithm', name(PK_ALGOS, d[3])]);
      if (d[0] === 3) f.push(['Signer key ID', hex(d.subarray(4, 12)).toUpperCase()]);
      break;
    case 5:
    case 7:
      p.warning = 'This is SECRET key material. Never share it!';
      keyFields(d, f);
      break;
    case 6:
    case 14:
      keyFields(d, f);
      break;
    case 8: {
      f.push(['Algorithm', name(COMP_ALGOS, d[0])]);
      const inner = d[0] === 0 ? d.subarray(1) : await inflate(d.subarray(1), d[0]).catch(() => null);
      if (inner) await walk(inner, depth + 1, out);
      else f.push(['Contents', 'not decompressed in browser']);
      break;
    }
    case 11: {
      const fmt = String.fromCharCode(d[0]);
      const nl = d[1];
      f.push(['Format', { b: 'binary', t: 'text', u: 'UTF-8 text', m: 'MIME' }[fmt] ?? fmt]);
      if (nl) f.push(['Filename', new TextDecoder().decode(d.subarray(2, 2 + nl))]);
      f.push(['Date', u32(d, 2 + nl) ? time(d, 2 + nl) : '(none)']);
      const content = d.subarray(6 + nl);
      f.push(['Data', `${content.length} bytes`]);
      if (fmt !== 'b' && content.length) f.push(['Preview', new TextDecoder().decode(content.subarray(0, 200))]);
      break;
    }
    case 13:
      f.push(['User ID', new TextDecoder().decode(d)]);
      break;
    case 18:
      f.push(['Version', String(d[0])]);
      f.push(['Contents', 'encrypted — needs the session key']);
      if (d[0] === 2) { f.push(['Cipher', name(SYM_ALGOS, d[1])]); f.push(['AEAD mode', String(d[2])]); }
      break;
  }
}

export async function inspect(text: string): Promise<{ type: string; packets: PacketInfo[]; cleartext?: string }> {
  const { type, data, cleartext } = dearmor(text);
  const packets: PacketInfo[] = [];
  await walk(data, 0, packets);
  return { type, packets, cleartext };
}
