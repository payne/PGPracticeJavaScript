// Stateless session: HMAC-SHA256 signed cookie containing the key fingerprint and expiry.
const COOKIE = 'pgps';
export const SESSION_TTL = 30 * 24 * 3600;

const enc = new TextEncoder();
const b64url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64url = (s: string) =>
  Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

async function hmacKey(secret: string) {
  if (!secret || secret.length < 32) throw new Error('SESSION_SECRET missing or too short');
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

export async function makeSessionCookie(secret: string, fingerprint: string, secure: boolean): Promise<string> {
  const payload = b64url(enc.encode(JSON.stringify({ f: fingerprint, e: Math.floor(Date.now() / 1000) + SESSION_TTL })));
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(payload)));
  return `${COOKIE}=${payload}.${b64url(sig)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL}${secure ? '; Secure' : ''}`;
}

export function clearSessionCookie(secure: boolean): string {
  return `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure ? '; Secure' : ''}`;
}

export async function readSession(secret: string, cookieHeader: string | null | undefined): Promise<string | null> {
  if (!cookieHeader) return null;
  const m = cookieHeader.match(new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`));
  if (!m) return null;
  const [payload, sig] = m[1].split('.');
  if (!payload || !sig) return null;
  try {
    const ok = await crypto.subtle.verify('HMAC', await hmacKey(secret), fromB64url(sig), enc.encode(payload));
    if (!ok) return null;
    const { f, e } = JSON.parse(new TextDecoder().decode(fromB64url(payload)));
    if (typeof f !== 'string' || typeof e !== 'number' || e < Date.now() / 1000) return null;
    return f;
  } catch {
    return null;
  }
}
