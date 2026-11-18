// Byte encodings in plain ECMAScript: no Buffer, atob/btoa, TextEncoder or TextDecoder,
// so the same code runs on Node, browsers and Hermes (React Native).
// Every decoder is strict and throws TypeError on any non-canonical input.

const STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function reverse(alphabet: string): Int16Array {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < alphabet.length; i++) table[alphabet.charCodeAt(i)] = i;
  return table;
}
const STD_REV = reverse(STD);
const URL_REV = reverse(URL);

function encode(bytes: Uint8Array, alphabet: string, pad: boolean): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out += alphabet[n >> 18]! + alphabet[(n >> 12) & 63]! + alphabet[(n >> 6) & 63]! + alphabet[n & 63]!;
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i]! << 16;
    out += alphabet[n >> 18]! + alphabet[(n >> 12) & 63]! + (pad ? '==' : '');
  } else if (rest === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out += alphabet[n >> 18]! + alphabet[(n >> 12) & 63]! + alphabet[(n >> 6) & 63]! + (pad ? '=' : '');
  }
  return out;
}

/** Decodes unpadded base64 digits; rejects unknown characters and non-zero trailing bits. */
function decodeDigits(s: string, table: Int16Array): Uint8Array {
  if (s.length % 4 === 1) throw new TypeError('invalid base64 length');
  const out = new Uint8Array(Math.floor((s.length * 3) / 4));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const v = c < 128 ? table[c]! : -1;
    if (v < 0) throw new TypeError('invalid base64 character');
    acc = ((acc << 6) | v) & 0xffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  if ((acc & ((1 << bits) - 1)) !== 0) throw new TypeError('non-canonical base64 (trailing bits)');
  return out;
}

export function base64UrlEncode(bytes: Uint8Array): string {
  return encode(bytes, URL, false);
}

/** Strict base64url without padding (RFC 7515 section 2). */
export function base64UrlDecode(s: string): Uint8Array {
  return decodeDigits(s, URL_REV);
}

export function base64Encode(bytes: Uint8Array): string {
  return encode(bytes, STD, true);
}

/** Strict standard base64 with mandatory padding and no whitespace (RFC 4648 section 4). */
export function base64Decode(s: string): Uint8Array {
  if (s.length % 4 !== 0) throw new TypeError('invalid base64 length');
  const padding = s.endsWith('==') ? 2 : s.endsWith('=') ? 1 : 0;
  return decodeDigits(s.slice(0, s.length - padding), STD_REV);
}

export function utf8Encode(s: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) {
    let cp = s.charCodeAt(i);
    if (cp >= 0xd800 && cp <= 0xdbff) {
      const lo = s.charCodeAt(i + 1);
      if (!(lo >= 0xdc00 && lo <= 0xdfff)) throw new TypeError('lone surrogate');
      cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
      i++;
    } else if (cp >= 0xdc00 && cp <= 0xdfff) {
      throw new TypeError('lone surrogate');
    }
    if (cp < 0x80) out.push(cp);
    else if (cp < 0x800) out.push(0xc0 | (cp >> 6), 0x80 | (cp & 63));
    else if (cp < 0x10000) out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
    else out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
  }
  return Uint8Array.from(out);
}

/** Strict UTF-8 decoding: rejects overlong forms, surrogates and code points above U+10FFFF. */
export function utf8Decode(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; ) {
    const c = bytes[i++]!;
    let cp: number;
    let n: number;
    if (c < 0x80) [cp, n] = [c, 0];
    else if (c >= 0xc2 && c < 0xe0) [cp, n] = [c & 0x1f, 1];
    else if (c >= 0xe0 && c < 0xf0) [cp, n] = [c & 0x0f, 2];
    else if (c >= 0xf0 && c < 0xf5) [cp, n] = [c & 0x07, 3];
    else throw new TypeError('invalid UTF-8');
    for (let k = 0; k < n; k++) {
      const x = bytes[i++];
      if (x === undefined || (x & 0xc0) !== 0x80) throw new TypeError('invalid UTF-8');
      cp = (cp << 6) | (x & 0x3f);
    }
    if ((n === 2 && (cp < 0x800 || (cp >= 0xd800 && cp < 0xe000))) || (n === 3 && (cp < 0x10000 || cp > 0x10ffff))) {
      throw new TypeError('invalid UTF-8');
    }
    s += String.fromCodePoint(cp);
  }
  return s;
}

export function hexEncode(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

/** Lowercase or uppercase hex, even length, nothing else. */
export function hexDecode(s: string): Uint8Array {
  if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) throw new TypeError('invalid hex');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
