// Backup catalogue (ADR-0009 section 5, ADR-0014 section 2): the list of documents the wallet
// holds, as document type and issuer only. It goes into the phone's own backup so a new phone
// can ask for each document again; no ids, keys, claim values, credentials or timestamps.

export interface CatalogueItem {
  vct: string;
  issuer: string;
}

export interface Catalogue {
  version: 1;
  items: CatalogueItem[];
}

export const MAX_CATALOGUE_LENGTH = 65536;
const MAX_ITEMS = 500;
const MAX_FIELD_LENGTH = 2048;

const itemKey = (i: CatalogueItem): string => JSON.stringify([i.vct, i.issuer]);

/**
 * One item per distinct (vct, issuer), sorted, so neither batch copies nor the order of issuance
 * show. Accepts credential rows or metadata; only `vct` and `issuer` are read.
 */
export function buildCatalogue(rows: readonly CatalogueItem[]): Catalogue {
  const unique = new Map<string, CatalogueItem>();
  for (const r of rows) {
    if (typeof r.vct !== 'string' || r.vct.length === 0 || typeof r.issuer !== 'string' || r.issuer.length === 0) {
      throw new TypeError('every row needs a non-empty vct and issuer');
    }
    unique.set(itemKey(r), { vct: r.vct, issuer: r.issuer });
  }
  const keys = [...unique.keys()].sort();
  return { version: 1, items: keys.map((k) => unique.get(k)!) };
}

export function serializeCatalogue(catalogue: Catalogue): string {
  return JSON.stringify({ version: 1, items: catalogue.items.map((i) => ({ vct: i.vct, issuer: i.issuer })) });
}

const hasExactKeys = (o: object, keys: string[]): boolean => {
  const own = Object.keys(o);
  return own.length === keys.length && keys.every((k) => own.includes(k));
};
const isField = (v: unknown): v is string => typeof v === 'string' && v.length > 0 && v.length <= MAX_FIELD_LENGTH;

/** Strict parse: exactly `{ version: 1, items: [{ vct, issuer }] }`, no duplicates. Null on anything else. */
export function parseCatalogue(text: string): Catalogue | null {
  if (typeof text !== 'string' || text.length > MAX_CATALOGUE_LENGTH) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed) || !hasExactKeys(parsed, ['version', 'items'])) return null;
  const { version, items } = parsed as { version: unknown; items: unknown };
  if (version !== 1 || !Array.isArray(items) || items.length > MAX_ITEMS) return null;
  const out: CatalogueItem[] = [];
  const seen = new Set<string>();
  for (const item of items as unknown[]) {
    if (typeof item !== 'object' || item === null || Array.isArray(item) || !hasExactKeys(item, ['vct', 'issuer'])) return null;
    const { vct, issuer } = item as { vct: unknown; issuer: unknown };
    if (!isField(vct) || !isField(issuer)) return null;
    const key = itemKey({ vct, issuer });
    if (seen.has(key)) return null;
    seen.add(key);
    out.push({ vct, issuer });
  }
  return { version: 1, items: out };
}

/** The catalogue items for which `currentRows` hold no credential: what to ask for again. */
export function diffCatalogue(catalogue: Catalogue, currentRows: readonly CatalogueItem[]): CatalogueItem[] {
  const held = new Set(currentRows.map(itemKey));
  return catalogue.items.filter((i) => !held.has(itemKey(i)));
}

/**
 * The catalogue to back up after the wallet's holdings changed: the previous items plus every item
 * held now, minus the items in `removed` that are no longer held. On a restored phone the vault
 * starts empty, so receiving the first document again must not drop the others still to request.
 * Pure; sorted like buildCatalogue; throws TypeError past the limits parseCatalogue accepts.
 */
export function mergeCatalogue(previous: Catalogue, rowsNowHeld: readonly CatalogueItem[], removed: readonly CatalogueItem[] = []): Catalogue {
  const held = new Set(rowsNowHeld.map(itemKey));
  const dropped = new Set(removed.map(itemKey).filter((k) => !held.has(k)));
  const merged = buildCatalogue([...previous.items.filter((i) => !dropped.has(itemKey(i))), ...rowsNowHeld]);
  if (merged.items.length > MAX_ITEMS || merged.items.some((i) => !isField(i.vct) || !isField(i.issuer))) {
    throw new TypeError(`a catalogue holds at most ${MAX_ITEMS} items of at most ${MAX_FIELD_LENGTH} characters per field`);
  }
  return merged;
}
