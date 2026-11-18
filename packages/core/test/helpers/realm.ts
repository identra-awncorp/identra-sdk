// A node:vm realm with ECMAScript built-ins only, plus what React Native provides (TextEncoder,
// atob, btoa) and a TextDecoder polyfill. No crypto, Buffer, process, fetch, require or window.
import vm from 'node:vm';

export function restrictedRealm(options: { textDecoder?: boolean } = {}): vm.Context {
  const ctx = vm.createContext({});
  // TextEncoder is defined inside the realm so that it returns this realm's Uint8Array, as on Hermes.
  vm.runInContext(
    `{ const u = unescape, e = encodeURIComponent, U8 = Uint8Array, S = String;
      globalThis.TextEncoder = class TextEncoder {
        get encoding() { return 'utf-8'; }
        encode(s = '') { const b = u(e(S(s))); const o = new U8(b.length); for (let i = 0; i < b.length; i++) o[i] = b.charCodeAt(i); return o; }
      }; }`,
    ctx,
  );
  Object.assign(ctx, { atob, btoa }, options.textDecoder === false ? {} : { TextDecoder });
  return ctx;
}

/** Names of the globals of a fresh realm before anything is added: the ECMAScript built-ins. */
export const ECMASCRIPT_GLOBALS = new Set(Object.getOwnPropertyNames(vm.runInNewContext('globalThis')));
