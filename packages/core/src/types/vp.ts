import type { IdentraProof } from './proof.js';
import type { IdentraVerifiableCredential } from './vc.js';

export interface IdentraVerifiablePresentation {
  '@context': Array<string | Record<string, unknown>>;
  id: string;
  type: string[];
  holder: string;
  verifiableCredential: IdentraVerifiableCredential[];
  proof?: IdentraProof;
}
