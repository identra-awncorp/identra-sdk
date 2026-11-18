// The product-chain world of the sdk-core tests (core/test/helpers/product.ts, compiled by the
// typecheck step before tests run) served over a node:http listener on 127.0.0.1: the canonical
// API URL of each route is the listener's URL with the canonical origin in front.
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

export const CANONICAL = 'https://api-identra.awncorp.vn';

type Route = { status: number; body: string } | Error;
export interface World {
  now: Date;
  root: Uint8Array;
  served: { routes: Record<string, Route> };
  chain(n?: number): Promise<string[]>;
  craft(org: string, payload: Record<string, unknown>): Promise<string>;
}
interface Helpers {
  productWorld(o?: { issuers?: unknown[] }): Promise<World>;
  trustIssuer(org: string): unknown;
  GTIN: string;
  SERIAL: string;
  CODE: string;
  TIMES: string[];
  statusUriOf(org: string): string;
}
export const helpers = (await import(new URL('../../core/test-dist/helpers/product.js', import.meta.url).href)) as Helpers;
export const eventsPath = (gtin = helpers.GTIN, serial = helpers.SERIAL) => `/v1/products/${gtin}/${serial}/events`;

/**
 * Serves `world` on 127.0.0.1:`port`. `handlers` (by request path) override the world's routes;
 * an unknown path is a 404. Every request path is recorded.
 */
export async function serve(port: number) {
  const state: { world?: World; handlers: Record<string, (req: IncomingMessage, res: ServerResponse) => void>; requests: string[] } = { handlers: {}, requests: [] };
  const server = createServer((req, res) => {
    const path = req.url ?? '';
    state.requests.push(path);
    const handler = state.handlers[path];
    if (handler) return handler(req, res);
    const route = state.world?.served.routes[CANONICAL + path];
    if (!route || route instanceof Error) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(route.status, { 'content-type': 'application/octet-stream' }).end(route.body);
  });
  await new Promise<void>((resolve) => server.listen(port, '127.0.0.1', resolve));
  return {
    state,
    baseUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    close: () => new Promise<void>((resolve) => { server.closeAllConnections(); server.close(() => resolve()); }),
  };
}

export const json = (status: number, body: unknown) => (_req: IncomingMessage, res: ServerResponse) =>
  void res.writeHead(status, { 'content-type': 'application/json', date: 'Wed, 18 Nov 2026 10:00:00 GMT' }).end(typeof body === 'string' ? body : JSON.stringify(body));
