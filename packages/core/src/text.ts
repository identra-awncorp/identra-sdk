// The one rule for text the SDK hands to a UI to show a person (a verifier's purpose, names and
// claims of a verification result). Its own entry point, `@identra/sdk-core/text`, so a browser
// bundle can use it without the rest of sdk-core.

/**
 * Characters that are invisible or can reorder or disguise displayed text: C0 and C1 controls and
 * DEL, the soft hyphen, the Arabic letter mark, zero-width characters and LRM / RLM, the line and
 * paragraph separators, the bidirectional embeddings, overrides and isolates, the BOM, and the tag
 * block U+E0000-E007F. Text containing any of them is refused (or dropped), never shown.
 */
export const UNSAFE_DISPLAY_TEXT = /[\u0000-\u001F\u007F-\u009F\u00AD\u061C\u200B-\u200F\u2028-\u202E\u2066-\u2069\uFEFF\u{E0000}-\u{E007F}]/u;

