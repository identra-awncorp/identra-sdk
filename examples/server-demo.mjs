import { createDemoDidDocument } from '@identra/sdk-core';
import { createIdentraServerSdk } from '@identra/sdk-server';

const serverSdk = createIdentraServerSdk();
const issuerDid = 'did:identra:demo:issuer';
const holderDid = 'did:identra:demo:holder';

await serverSdk.registerDidDocument(createDemoDidDocument(issuerDid));
await serverSdk.registerDidDocument(createDemoDidDocument(holderDid));

const credential = await serverSdk.issueCredential({
  issuerDid,
  subjectDid: holderDid,
  type: 'UniversityDegreeCredential',
  claims: {
    degree: 'Software Engineering',
    gpa: '3.85 / 4.0'
  }
});

const credentialResult = await serverSdk.verifyCredential(credential);
const request = serverSdk.createPresentationRequest({
  verifier: 'did:identra:demo:verifier',
  definitionId: 'degree-presentation',
  descriptorId: 'degree-proof',
  schema: ['UniversityDegreeCredential']
});
const session = await serverSdk.createVerificationSession(request);

if (!credentialResult.valid) {
  throw new Error(`Server SDK did not verify issued credential: ${credentialResult.errors.join('; ')}`);
}

console.log('server-demo ok', {
  package: '@identra/sdk-server',
  credentialId: credential.id,
  sessionId: session.id
});
