import type { IdentraCredentialOffer, IdentraPresentationRequest } from '../types/exchange.js';
import { invalid, type ValidationResult } from './validation-result.js';

export function validateCredentialOffer(offer: IdentraCredentialOffer): ValidationResult {
  const errors: string[] = [];

  if (offer.protocol !== 'identra-demo-oid4vci') errors.push('Credential offer protocol is invalid.');
  if (!offer.credential_issuer) errors.push('Credential offer issuer is required.');
  if (!Array.isArray(offer.credential_configuration_ids) || offer.credential_configuration_ids.length === 0) {
    errors.push('Credential offer must include credential configuration ids.');
  }

  return invalid(errors);
}

export function validatePresentationRequest(request: IdentraPresentationRequest): ValidationResult {
  const errors: string[] = [];

  if (request.protocol !== 'identra-demo-oid4vp') errors.push('Presentation request protocol is invalid.');
  if (!request.client_id) errors.push('Presentation request client_id is required.');
  if (request.response_type !== 'vp_token') errors.push('Presentation request response_type must be vp_token.');
  if (!request.nonce) errors.push('Presentation request nonce is required.');
  if (!request.presentation_definition?.id) errors.push('Presentation definition id is required.');
  if (!Array.isArray(request.presentation_definition?.input_descriptors)) {
    errors.push('Presentation definition input_descriptors array is required.');
  }

  return invalid(errors);
}
