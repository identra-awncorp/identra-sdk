import type { IdentraVerifiablePresentation } from '../types/vp.js';
import { invalid, type ValidationResult } from './validation-result.js';

export function validatePresentation(presentation: IdentraVerifiablePresentation): ValidationResult {
  const errors: string[] = [];

  if (!presentation || typeof presentation !== 'object') errors.push('Presentation must be an object.');
  if (!Array.isArray(presentation['@context']) || presentation['@context'].length === 0) {
    errors.push('Presentation must include at least one @context.');
  }
  if (!presentation.id) errors.push('Presentation id is required.');
  if (!Array.isArray(presentation.type) || !presentation.type.includes('VerifiablePresentation')) {
    errors.push('Presentation type must include VerifiablePresentation.');
  }
  if (!presentation.holder) errors.push('Presentation holder is required.');
  if (!Array.isArray(presentation.verifiableCredential)) {
    errors.push('Presentation must include verifiableCredential array.');
  }

  return invalid(errors);
}
