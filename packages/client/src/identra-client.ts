import {
  createDemoPresentationRequest,
  type IdentraPresentationRequest,
  type PresentationInputDescriptor,
  validatePresentationRequest,
  type VerificationSession
} from '@identra/sdk-core';

export interface IdentraFetchResponse {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}

export type IdentraFetch = (
  url: string,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
  }
) => Promise<IdentraFetchResponse>;

export interface IdentraClientConfig {
  apiBaseUrl: string;
  fetch?: IdentraFetch;
  deepLinkScheme?: string;
}

export interface CreatePresentationRequestInput {
  verifierDid: string;
  definitionId?: string;
  descriptors: PresentationInputDescriptor[];
  responseUri?: string;
  redirectUri?: string;
  state?: string;
}

export interface IdentraClientSdk {
  createPresentationRequest(input: CreatePresentationRequestInput): IdentraPresentationRequest;
  createPresentationDeepLink(request: IdentraPresentationRequest): string;
  createPresentationQrPayload(request: IdentraPresentationRequest): string;
  getVerificationSession(sessionId: string): Promise<VerificationSession>;
}

export function createIdentraClient(config: IdentraClientConfig): IdentraClientSdk {
  const apiBaseUrl = config.apiBaseUrl.replace(/\/+$/, '');
  const deepLinkScheme = config.deepLinkScheme ?? 'identra';

  return {
    createPresentationRequest(input) {
      const request = createDemoPresentationRequest({
        verifier: input.verifierDid,
        definitionId: input.definitionId ?? 'identra-presentation-definition',
        descriptorId: input.descriptors[0]?.id ?? 'identra-input-descriptor',
        schema: input.descriptors[0]?.schema
      });

      const hydratedRequest: IdentraPresentationRequest = {
        ...request,
        presentation_definition: {
          ...request.presentation_definition,
          input_descriptors: input.descriptors
        },
        response_uri: input.responseUri,
        redirect_uri: input.redirectUri,
        state: input.state
      };

      const validation = validatePresentationRequest(hydratedRequest);
      if (!validation.valid) {
        throw new Error(`Invalid presentation request: ${validation.errors.join('; ')}`);
      }

      return hydratedRequest;
    },

    createPresentationDeepLink(request) {
      const payload = encodeURIComponent(JSON.stringify(request));
      return `${deepLinkScheme}://present?request=${payload}`;
    },

    createPresentationQrPayload(request) {
      return this.createPresentationDeepLink(request);
    },

    async getVerificationSession(sessionId) {
      if (!config.fetch) {
        throw new Error('Identra client fetch adapter is required for server API calls.');
      }

      const response = await config.fetch(`${apiBaseUrl}/v1/verification/sessions/${sessionId}`);
      if (!response.ok) {
        throw new Error(`Failed to load verification session: HTTP ${response.status}`);
      }

      return (await response.json()) as VerificationSession;
    }
  };
}
