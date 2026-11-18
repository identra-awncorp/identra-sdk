// The one place sdk-app draws from the injected RandomSource.
import { sha256 } from '@noble/hashes/sha2.js';
import type { RandomSource } from '@identra/sdk-core';

/** The RandomSource returned something unusable. Carries no bytes. */
export class RandomSourceError extends Error {
  constructor() {
    super('RandomSource returned unusable output');
    this.name = 'RandomSourceError';
  }
}

const MIN_DRAW = 12;
/** Per RandomSource and length: SHA-256 of the previous block (never the block itself, which may be a key seed). */
const previous = new WeakMap<RandomSource, Map<number, Uint8Array>>();

/**
 * `n` bytes (n >= 12) from `random`, rejecting two gross failures with RandomSourceError: a block
 * whose bytes are all equal (an all-zero polyfill; false positive 2^-8(n-1), at most 2^-88 here),
 * and a block identical to the previous block of the same length from the same RandomSource (a
 * source that repeats). This catches only the typical broken polyfill; it is not a health test
 * and says nothing about the quality of output that passes.
 */
export function drawRandom(random: RandomSource, n: number): Uint8Array {
  if (!Number.isInteger(n) || n < MIN_DRAW) throw new TypeError(`draws are at least ${MIN_DRAW} bytes`);
  const block = random.bytes(n);
  if (!(block instanceof Uint8Array) || block.length !== n) throw new RandomSourceError();
  let acc = 0;
  for (const b of block) acc |= b ^ block[0]!;
  const digest = sha256(block);
  let byLength = previous.get(random);
  if (!byLength) previous.set(random, (byLength = new Map()));
  const last = byLength.get(n);
  let same = last !== undefined ? 0 : 1;
  if (last !== undefined) for (let i = 0; i < digest.length; i++) same |= digest[i]! ^ last[i]!;
  byLength.set(n, digest);
  if (acc === 0 || same === 0) {
    block.fill(0);
    throw new RandomSourceError();
  }
  return block;
}
