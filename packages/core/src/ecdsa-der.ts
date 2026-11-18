// ECDSA P-256 signature conversion between DER (X.509, Android Keystore) and the 64-byte
// r||s form used by JOSE and the Verifier interface.

const SIZE = 32;

/**
 * Strict DER `SEQUENCE { INTEGER r, INTEGER s }` -> 64-byte r||s.
 * Rejects long-form or non-minimal lengths, negative / non-minimal / zero / oversized integers
 * and trailing bytes. Throws TypeError on malformed input.
 */
export function derSignatureToRaw(der: Uint8Array): Uint8Array {
  let p = 0;
  const byte = (): number => {
    const b = der[p++];
    if (b === undefined) throw new TypeError('truncated DER signature');
    return b;
  };
  const length = (): number => {
    const l = byte();
    if (l < 0x80) return l;
    if (l !== 0x81) throw new TypeError('unsupported DER length');
    const v = byte();
    if (v < 0x80) throw new TypeError('non-minimal DER length');
    return v;
  };
  if (byte() !== 0x30) throw new TypeError('DER signature is not a SEQUENCE');
  if (length() !== der.length - p) throw new TypeError('DER SEQUENCE length mismatch');
  const out = new Uint8Array(SIZE * 2);
  for (let k = 0; k < 2; k++) {
    if (byte() !== 0x02) throw new TypeError('DER signature component is not an INTEGER');
    const l = length();
    if (l === 0 || p + l > der.length) throw new TypeError('bad INTEGER length');
    let v = der.subarray(p, p + l);
    p += l;
    if (v[0]! & 0x80) throw new TypeError('negative INTEGER');
    if (l > 1 && v[0] === 0 && !(v[1]! & 0x80)) throw new TypeError('non-minimal INTEGER');
    if (v[0] === 0) v = v.subarray(1);
    if (v.length === 0) throw new TypeError('zero INTEGER');
    if (v.length > SIZE) throw new TypeError('INTEGER too large for P-256');
    out.set(v, SIZE * (k + 1) - v.length);
  }
  if (p !== der.length) throw new TypeError('trailing bytes after DER signature');
  return out;
}

/** 64-byte r||s -> minimal DER `SEQUENCE { INTEGER r, INTEGER s }`. Throws TypeError on bad input. */
export function rawSignatureToDer(raw: Uint8Array): Uint8Array {
  if (raw.length !== SIZE * 2) throw new TypeError('raw P-256 signature must be 64 bytes');
  const integer = (v: Uint8Array): number[] => {
    let i = 0;
    while (i < v.length - 1 && v[i] === 0) i++;
    const body = Array.from(v.subarray(i));
    if (body.length === 1 && body[0] === 0) throw new TypeError('zero INTEGER');
    if (body[0]! & 0x80) body.unshift(0);
    return [0x02, body.length, ...body];
  };
  const content = [...integer(raw.subarray(0, SIZE)), ...integer(raw.subarray(SIZE))];
  // At most 2 * (2 + 33) = 70 bytes, so the short length form always suffices.
  return Uint8Array.from([0x30, content.length, ...content]);
}
