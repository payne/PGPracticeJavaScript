const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

export function randomCode(groups = 3, size = 4): string {
  const bytes = crypto.getRandomValues(new Uint8Array(groups * size));
  const chars = Array.from(bytes, (b) => CODE_ALPHABET[b % CODE_ALPHABET.length]);
  const parts: string[] = [];
  for (let i = 0; i < groups; i++) parts.push(chars.slice(i * size, (i + 1) * size).join(''));
  return parts.join('-');
}

const WORDS = (
  'amber anchor apple arrow aspen badger banjo beacon birch bison cactus canyon cedar cobalt comet coral ' +
  'cricket delta dingo ember falcon fern fjord garnet glacier harbor hazel heron indigo iris jasper juniper ' +
  'kayak kestrel lagoon lantern lemon lilac lynx maple marble meadow mango nebula nectar nutmeg oasis ocelot ' +
  'olive onyx orchid otter pebble pepper pine plume quartz quill raven reef ripple saffron sable sierra ' +
  'spruce tango thistle tundra umber velvet violet walnut willow yarrow zephyr zinnia'
).split(' ');

export function randomWords(n: number): string {
  const bytes = crypto.getRandomValues(new Uint16Array(n));
  return Array.from(bytes, (b) => WORDS[b % WORDS.length]).join(' ');
}

export function randomInt(max: number): number {
  return crypto.getRandomValues(new Uint32Array(1))[0] % max;
}

export async function sha256Hex(text: string): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(d), (b) => b.toString(16).padStart(2, '0')).join('');
}

export const normalizeCode = (s: string) => s.toUpperCase().replace(/[^A-Z0-9]/g, '');
export const normalizeWord = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, '');
export const normalizeFpr = (s: string) => s.toUpperCase().replace(/[^0-9A-F]/g, '');

export const now = () => Math.floor(Date.now() / 1000);
