import { createDemoDidDocument } from '@identra/sdk-core';
import { createDemoHolderSigner, createIdentraAppSdk, InMemoryCredentialStore } from '@identra/sdk-app';

const holderDid = 'did:identra:demo:holder';
const holderDocument = createDemoDidDocument(holderDid);

const resolver = {
  async resolve(did) {
    return {
      didDocument: did === holderDid ? holderDocument : null,
      didDocumentMetadata: {},
      didResolutionMetadata: did === holderDid ? { contentType: 'application/did+json' } : { error: 'notFound' }
    };
  }
};

const appSdk = createIdentraAppSdk({
  resolver,
  signer: createDemoHolderSigner({ holderDid }),
  credentialStore: new InMemoryCredentialStore()
});

await appSdk.acceptCredentialOffer({
  protocol: 'identra-demo-oid4vci',
  credential_issuer: 'did:identra:demo:issuer',
  credential_configuration_ids: ['UniversityDegreeCredential']
});

await appSdk.storeCredential({
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  id: 'urn:identra:vc:app-demo-degree',
  type: ['VerifiableCredential', 'UniversityDegreeCredential'],
  issuer: 'did:identra:demo:issuer',
  validFrom: new Date().toISOString(),
  credentialSubject: {
    id: holderDid,
    degree: 'Software Engineering'
  }
});

const credentials = await appSdk.listCredentials();
const presentation = await appSdk.createPresentation({
  holder: holderDid,
  credentials,
  request: {
    protocol: 'identra-demo-oid4vp',
    client_id: 'did:identra:demo:verifier',
    response_type: 'vp_token',
    response_mode: 'direct_post',
    nonce: 'app-demo-nonce',
    presentation_definition: {
      id: 'degree-presentation',
      input_descriptors: [{ id: 'degree-proof', schema: ['UniversityDegreeCredential'] }]
    }
  }
});

if (!presentation.proof) {
  throw new Error('App SDK did not sign a demo presentation.');
}

console.log('app-demo ok', {
  package: '@identra/sdk-app',
  credentials: credentials.length,
  proofType: presentation.proof.type
});
