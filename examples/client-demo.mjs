import { createIdentraClient } from '@identra/sdk-client';

const client = createIdentraClient({
  apiBaseUrl: 'http://localhost:4000',
  deepLinkScheme: 'identra'
});

const request = client.createPresentationRequest({
  verifierDid: 'did:identra:demo:verifier',
  descriptors: [
    {
      id: 'degree-proof',
      name: 'Degree proof',
      schema: ['UniversityDegreeCredential']
    }
  ],
  state: 'client-demo'
});

const qrPayload = client.createPresentationQrPayload(request);

if (!qrPayload.startsWith('identra://present?request=')) {
  throw new Error('Client SDK did not create a presentation QR payload.');
}

console.log('client-demo ok', {
  package: '@identra/sdk-client',
  protocol: request.protocol,
  qrPayloadPrefix: qrPayload.slice(0, 25)
});
