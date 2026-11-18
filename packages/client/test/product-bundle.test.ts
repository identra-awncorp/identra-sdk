// Browser safety and weight of the two entry points: the main entry bundles without any sdk-core
// runtime code, and @identra/sdk-client/product, bundled with esbuild --platform=neutral, verifies a
// served chain inside a node:vm realm that has browser globals (WebCrypto, fetch, timers,
// AbortController, TextEncoder / TextDecoder) but no Buffer, process or require.
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import vm from 'node:vm';
import * as esbuild from 'esbuild';
import { eventsPath, helpers, json, serve } from './product-world.js';

const testDist = new URL('.', import.meta.url).pathname;
const bundle = async (contents: string) => {
  const built = await esbuild.build({
    bundle: true, platform: 'neutral', mainFields: ['module', 'main'], minify: true, format: 'iife', globalName: 'Bundle',
    write: false, logLevel: 'silent', stdin: { contents, resolveDir: testDist },
  });
  return built.outputFiles[0]!.text;
};

test('the main entry carries no sdk-core runtime code and nothing of the product entry', async (t) => {
  const code = await bundle(`export * from '@identra/sdk-client';`);
  t.diagnostic(`@identra/sdk-client main entry: ${code.length} bytes minified`);
  for (const marker of ['createProductVerifier', 'CHAIN_BROKEN', 'product_chain', 'statuslist+jwt', 'subtle']) assert.equal(code.includes(marker), false, marker);
  assert.ok(code.length < 10_000);
});

test('the product entry runs in a browser-like realm without Buffer or process and verifies a served chain', async (t) => {
  const code = await bundle(`export { createProductVerifier } from '@identra/sdk-client/product';`);
  t.diagnostic(`@identra/sdk-client/product: ${code.length} bytes minified`);
  const server = await serve(47661);
  after(server.close);
  const world = await helpers.productWorld();
  server.state.world = world;
  server.state.handlers = { [eventsPath()]: json(200, { gtin: helpers.GTIN, serial: helpers.SERIAL, events: await world.chain(3) }) };

  const ctx = vm.createContext({ crypto: globalThis.crypto, fetch, setTimeout, clearTimeout, AbortController, TextEncoder, TextDecoder });
  assert.equal(vm.runInContext('[typeof Buffer, typeof process, typeof require, typeof window].join()', ctx), 'undefined,undefined,undefined,undefined');
  vm.runInContext(code, ctx);
  Object.assign(ctx, { input: { apiBaseUrl: server.baseUrl, root: [...world.root], now: world.now.getTime(), gtin: helpers.GTIN, serial: helpers.SERIAL } });
  const view = await vm.runInContext(
    `Bundle.createProductVerifier({ apiBaseUrl: input.apiBaseUrl, rootCertificates: [new Uint8Array(input.root)], now: () => input.now }).load(input.gtin, input.serial)`,
    ctx,
  );
  assert.equal(view.state, 'ok');
  assert.deepEqual({ ok: view.result.ok, complete: view.result.complete }, { ok: true, complete: true });
});
