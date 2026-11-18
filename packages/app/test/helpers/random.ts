// RandomSource fakes for the tests.
import type { RandomSource } from '@identra/sdk-core';
import { webCryptoRandom } from '@identra/sdk-core/webcrypto';

/** Real randomness, with every request recorded. */
export function countingRandom(inner: RandomSource = webCryptoRandom): RandomSource & { calls: number[] } {
  const calls: number[] = [];
  return {
    calls,
    bytes(n) {
      calls.push(n);
      return inner.bytes(n);
    },
  };
}

/** Every byte the same value. */
export const constantRandom = (value: number): RandomSource => ({ bytes: (n) => new Uint8Array(n).fill(value) });

/** Deterministic, distinct output per call (a counter run through a simple mix); not secure. */
export function seededRandom(seed: number): RandomSource {
  let state = seed >>> 0;
  return {
    bytes(n) {
      const out = new Uint8Array(n);
      for (let i = 0; i < n; i++) {
        state = (Math.imul(state ^ (state >>> 15), 0x2c1b3c6d) + 0x9e3779b9) >>> 0;
        out[i] = state >>> 24;
      }
      return out;
    },
  };
}

/** Returns the queued byte arrays in order, then fails. */
export function queuedRandom(...queue: Uint8Array[]): RandomSource {
  return {
    bytes(n) {
      const next = queue.shift();
      if (!next || next.length !== n) throw new Error(`unexpected request for ${n} random bytes`);
      return next.slice();
    },
  };
}
