import type { IdentraDidDocument } from '../types/did.js';
import { invalid, type ValidationResult } from './validation-result.js';

const DID_PATTERN = /^did:[a-z0-9]+:[A-Za-z0-9._:%-]+$/;

export function isDid(value: unknown): value is `did:${string}:${string}` {
  return typeof value === 'string' && DID_PATTERN.test(value);
}

export function validateDidDocument(document: IdentraDidDocument): ValidationResult {
  const errors: string[] = [];

  if (!document || typeof document !== 'object') errors.push('DID document must be an object.');
  if (!isDid(document.id)) errors.push('DID document id must be a valid DID.');
  if (!document['@context']) errors.push('DID document must include @context.');

  for (const method of document.verificationMethod ?? []) {
    if (!method.id) errors.push('Verification method id is required.');
    if (!method.type) errors.push(`Verification method ${method.id} type is required.`);
    if (!method.controller) errors.push(`Verification method ${method.id} controller is required.`);
  }

  return invalid(errors);
}
