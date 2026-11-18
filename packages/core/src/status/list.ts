// The Identra status list (ADR-0013 sections 1-2, ADR-0017 section 3): 131 072 entries of 2 bits,
// 0 valid, 1 revoked, 2 suspended. @owf/token-status-list does the bit packing (Token Status List
// section 4.1: index 0 in the least significant bits of byte 0) and the ZLIB (de)compression; this
// module adds what the library lacks: the fixed size, the 0-2 value range and bounded inflation.
// It is the only file that imports the library.
import { StatusList as LibraryStatusList } from '@owf/token-status-list';
import { base64UrlDecode, base64UrlEncode } from '../encoding.js';

export const STATUS_LIST_ENTRIES = 131_072;
/** Size of the raw (uncompressed) list: 2 bits per entry. */
export const STATUS_LIST_BYTES = STATUS_LIST_ENTRIES / 4;
export const STATUS_VALUE = Object.freeze({ valid: 0, revoked: 1, suspended: 2 } as const);
export type StatusValue = 0 | 1 | 2;

export interface StatusList {
  getStatus(idx: number): StatusValue;
  setStatus(idx: number, value: StatusValue): void;
  /** The raw 32 768-byte bit array, for storage. A copy. */
  toBytes(): Uint8Array;
  /** The `status_list` claim of a Status List Token. */
  encode(): { bits: 2; lst: string };
}

const isIndex = (idx: unknown): idx is number => Number.isSafeInteger(idx) && (idx as number) >= 0 && (idx as number) < STATUS_LIST_ENTRIES;
const isValue = (v: unknown): v is StatusValue => v === 0 || v === 1 || v === 2;

function wrap(list: LibraryStatusList): StatusList {
  return {
    getStatus(idx) {
      if (!isIndex(idx)) throw new RangeError(`status list index must be an integer in [0, ${STATUS_LIST_ENTRIES})`);
      return list.getStatus(idx) as StatusValue;
    },
    setStatus(idx, value) {
      if (!isIndex(idx)) throw new RangeError(`status list index must be an integer in [0, ${STATUS_LIST_ENTRIES})`);
      if (!isValue(value)) throw new RangeError('status value must be 0 (valid), 1 (revoked) or 2 (suspended)');
      list.setStatus(idx, value);
    },
    toBytes: () => list.encodeStatusListIntoByteArray(),
    encode: () => ({ bits: 2, lst: base64UrlEncode(list.compressStatusListToBytes()) }),
  };
}

/** A new list with every entry 0 (valid). */
export function createStatusList(): StatusList {
  return wrap(new LibraryStatusList(new Array<number>(STATUS_LIST_ENTRIES).fill(0), 2));
}

/** A list from its raw bit array (toBytes). Throws TypeError unless it is exactly 32 768 bytes of values 0-2. */
export function statusListFromBytes(bytes: Uint8Array): StatusList {
  if (!(bytes instanceof Uint8Array) || bytes.length !== STATUS_LIST_BYTES) throw new TypeError(`a status list is exactly ${STATUS_LIST_BYTES} bytes`);
  const values = new Array<number>(STATUS_LIST_ENTRIES);
  for (let i = 0; i < STATUS_LIST_ENTRIES; i++) {
    // Token Status List section 4.1: entry i is bits 2*(i mod 4) and up of byte floor(i / 4).
    const v = (bytes[i >> 2]! >> ((i & 3) * 2)) & 3;
    if (!isValue(v)) throw new TypeError(`status list entry ${i} has the value 3, which is not defined`);
    values[i] = v;
  }
  return wrap(new LibraryStatusList(values, 2));
}

/**
 * The list of a `status_list` claim. Throws TypeError unless `bits` is 2 and `lst` is base64url of
 * one ZLIB stream that inflates to exactly 32 768 bytes of values 0-2. Inflation stops with an error
 * as soon as the output exceeds 32 768 bytes (the library inflates in 64 KiB output chunks, so at
 * most one chunk is produced before it stops): a small `lst` cannot exhaust memory.
 */
export function decodeStatusList(claim: unknown): StatusList {
  const c = claim as { bits?: unknown; lst?: unknown } | null;
  if (typeof c !== 'object' || c === null || Array.isArray(c)) throw new TypeError('status_list is not an object');
  if (c.bits !== 2) throw new TypeError('status_list.bits must be 2');
  if (typeof c.lst !== 'string' || c.lst === '') throw new TypeError('status_list.lst must be a non-empty string');
  let raw: Uint8Array;
  try {
    const inflated = LibraryStatusList.decompressStatusListFromBytes(base64UrlDecode(c.lst), 2, undefined, { maxDecompressedBytes: STATUS_LIST_BYTES });
    raw = inflated.encodeStatusListIntoByteArray();
  } catch {
    throw new TypeError(`status_list.lst is not base64url of a ZLIB stream of at most ${STATUS_LIST_BYTES} bytes`);
  }
  return statusListFromBytes(raw);
}
