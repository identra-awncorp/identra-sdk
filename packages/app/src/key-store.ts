// Wallet keys (ADR-0009 section 1, 2): one P-256 key per credential, behind WalletKeyStore. This
// file holds the software store (secret scalar in the platform secret storage); a hardware-backed
// store is a later drop-in behind the same interface, built on createDerSigningAdapter.
import { base64UrlDecode, base64UrlEncode } from '@identra/sdk-core';
import type { EcPublicJwk, RandomSource, Signer } from '@identra/sdk-core';
import { createNobleSigner, generateSecretKey, P256, uncompressedPointToJwk } from './crypto/noble.js';
import { drawRandom } from './random.js';

/**
 * Small-secret storage, implemented by the app with expo-secure-store (`requireAuthentication:
 * true`, this-device-only keychain class) and by createInMemorySecretStorage for Node and tests.
 * Keys use only `[A-Za-z0-9._-]`; values are short ASCII strings.
 *
 * `get` must resolve null only when the item does not exist, and must reject when the storage is
 * unavailable (device locked, biometric prompt cancelled): a null is taken as "absent" and the
 * credential vault would then create a new data key. Reject with a SecretStorageError when the
 * platform says why: `KEY_INVALIDATED` (the item can never be read again, e.g. Android after a
 * biometric change), `CANCELLED` (the user dismissed the prompt), `LOCKED` (the device is locked);
 * the key store passes that code on. Any other rejection is reported as it is.
 */
export interface SecretStorage {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
}

/** In-memory SecretStorage for Node and tests. Pass a Map to inspect what was written. */
export function createInMemorySecretStorage(map: Map<string, string> = new Map()): SecretStorage {
  return {
    async get(key) {
      return map.get(key) ?? null;
    },
    async set(key, value) {
      map.set(key, value);
    },
    async delete(key) {
      map.delete(key);
    },
  };
}

export interface WalletKeyStore {
  /** A fresh key pair; `keyId` is what the credential row stores in `key_id`. */
  create(): Promise<{ keyId: string; publicJwk: EcPublicJwk }>;
  /**
   * Rejects with WalletKeyError: 'KEY_NOT_FOUND' for an unknown keyId, 'KEY_CORRUPT', or the code
   * of a SecretStorageError ('KEY_INVALIDATED', 'CANCELLED', 'LOCKED').
   */
  signer(keyId: string): Promise<Signer>;
  /** Idempotent. */
  delete(keyId: string): Promise<void>;
}

export type SecretStorageErrorCode = 'KEY_INVALIDATED' | 'CANCELLED' | 'LOCKED';
const STORAGE_CODES: readonly string[] = ['KEY_INVALIDATED', 'CANCELLED', 'LOCKED'];

/** What the app's SecretStorage adapter throws when the platform says why a read or write failed. */
export class SecretStorageError extends Error {
  readonly code: SecretStorageErrorCode;
  constructor(code: SecretStorageErrorCode) {
    super(`secret storage: ${code}`);
    this.name = 'SecretStorageError';
    this.code = code;
  }
}

/** True for a SecretStorageError, also one from another copy of this package (checked by name and code). */
export function isSecretStorageError(e: unknown): e is SecretStorageError {
  return e instanceof Error && e.name === 'SecretStorageError' && STORAGE_CODES.includes((e as { code?: unknown }).code as string);
}

export type WalletKeyErrorCode = 'KEY_NOT_FOUND' | 'KEY_CORRUPT' | SecretStorageErrorCode;
const KEY_MESSAGES: Record<WalletKeyErrorCode, string> = {
  KEY_NOT_FOUND: 'wallet key not found',
  KEY_CORRUPT: 'stored wallet key is corrupt',
  KEY_INVALIDATED: 'wallet key was invalidated by the platform',
  CANCELLED: 'the user cancelled the key prompt',
  LOCKED: 'the device is locked',
};

export class WalletKeyError extends Error {
  readonly code: WalletKeyErrorCode;
  constructor(code: WalletKeyErrorCode) {
    super(KEY_MESSAGES[code]);
    this.name = 'WalletKeyError';
    this.code = code;
  }
}

/** A SecretStorageError becomes the WalletKeyError of its code; anything else is rethrown. */
async function storageCall<T>(call: () => Promise<T>): Promise<T> {
  try {
    return await call();
  } catch (e) {
    throw isSecretStorageError(e) ? new WalletKeyError(e.code) : e;
  }
}

const KEY_ID = /^[A-Za-z0-9_-]{22}$/;
const secretName = (keyId: string): string => `identra.key.${keyId}`;

/**
 * Software WalletKeyStore: each key is one SecretStorage item `identra.key.<keyId>` holding the
 * base64url 32-byte scalar (43 characters). `keyId` is base64url of 128 random bits.
 *
 * A signer holds its scalar in memory: ask for it right before signing and drop it afterwards.
 * Decoded buffers are zeroed; the base64url string from the storage cannot be (JS strings are
 * immutable), so erasure is best-effort.
 */
export function createSoftwareKeyStore(options: { secrets: SecretStorage; random: RandomSource }): WalletKeyStore {
  const { secrets, random } = options;
  return {
    async create() {
      const id = drawRandom(random, 16);
      // No existence check before writing: with requireAuthentication a read prompts for biometrics.
      const keyId = base64UrlEncode(id);
      const secretKey = generateSecretKey(random);
      try {
        const publicJwk = uncompressedPointToJwk(P256.getPublicKey(secretKey, false));
        await storageCall(() => secrets.set(secretName(keyId), base64UrlEncode(secretKey)));
        return { keyId, publicJwk };
      } finally {
        secretKey.fill(0);
      }
    },

    async signer(keyId) {
      if (typeof keyId !== 'string' || !KEY_ID.test(keyId)) throw new WalletKeyError('KEY_NOT_FOUND');
      const stored = await storageCall(() => secrets.get(secretName(keyId)));
      if (stored === null) throw new WalletKeyError('KEY_NOT_FOUND');
      let secretKey: Uint8Array;
      try {
        secretKey = base64UrlDecode(stored);
      } catch {
        throw new WalletKeyError('KEY_CORRUPT');
      }
      try {
        if (!P256.utils.isValidSecretKey(secretKey)) throw new WalletKeyError('KEY_CORRUPT');
        return createNobleSigner(secretKey);
      } finally {
        secretKey.fill(0);
      }
    },

    async delete(keyId) {
      if (typeof keyId !== 'string' || !KEY_ID.test(keyId)) return;
      await secrets.delete(secretName(keyId));
    },
  };
}
