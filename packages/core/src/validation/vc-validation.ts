import type { IdentraVerifiableCredential } from '../types/vc.js';
import { invalid, type ValidationResult } from './validation-result.js';

export function validateCredential(credential: IdentraVerifiableCredential): ValidationResult {
  const errors: string[] = [];

  if (!credential || typeof credential !== 'object') errors.push('Credential must be an object.');
  if (!Array.isArray(credential['@context']) || credential['@context'].length === 0) {
    errors.push('Credential must include at least one @context.');
  }
  if (!credential.id) errors.push('Credential id is required.');
  if (!Array.isArray(credential.type) || !credential.type.includes('VerifiableCredential')) {
    errors.push('Credential type must include VerifiableCredential.');
  }
  if (!credential.issuer) errors.push('Credential issuer is required.');
  if (!credential.credentialSubject) errors.push('Credential subject is required.');

  return invalid(errors);
}
