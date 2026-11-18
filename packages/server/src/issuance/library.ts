// Adapter to @openid4vc/openid4vci, @openid4vc/oauth2 and jose for the issuer. The only file of the
// issuer that imports them, so a library upgrade touches one place. The library builds and
// validates the metadata and the offer, parses (and decrypts) credential requests and encrypts
// credential responses. It never signs or verifies anything here: access tokens and proofs are
// checked by our own code (access-token.ts, proof.ts).
import { Oauth2AuthorizationServer, Oauth2ServerErrorResponseError, preAuthorizedCodeGrantIdentifier } from '@openid4vc/oauth2';
import { Openid4vciIssuer, Openid4vciVersion, type CredentialOfferObject, type IssuerMetadataResult } from '@openid4vc/openid4vci';
import { CompactEncrypt, compactDecrypt, importJWK } from 'jose';
import { utf8Decode, utf8Encode, type EcPublicJwk, type Hasher, type RandomSource } from '@identra/sdk-core';

export const PRE_AUTHORIZED_GRANT = preAuthorizedCodeGrantIdentifier;
export type JweEnc = 'A128GCM' | 'A256GCM';
const ENC_VALUES: JweEnc[] = ['A256GCM', 'A128GCM'];

export interface Display {
  vi: string;
  en: string;
}
export interface ConfigurationMetadata {
  vct: string;
  display: Display;
  /** Claim names with their labels, in display order. */
  claims: { name: string; display: Display }[];
}

const displayList = (d: Display) => [
  { name: d.vi, locale: 'vi' },
  { name: d.en, locale: 'en' },
];

const notUsed = () => {
  throw new Error('the issuer never asks the OpenID4VC library to sign or verify');
};

function libraryIssuer(o: { hasher: Hasher; random: RandomSource; decryptionKey: CryptoKey }) {
  return new Openid4vciIssuer({
    callbacks: {
      hash: (data, alg) => {
        if (alg !== 'sha-256' && alg !== 'SHA-256') throw new TypeError('only SHA-256');
        return o.hasher.sha256(typeof data === 'string' ? utf8Encode(data) : new Uint8Array(data));
      },
      generateRandom: (n) => o.random.bytes(n),
      signJws: notUsed,
      verifyJws: notUsed,
      clientAuthentication: () => {},
      // Expected failures (wrong key, tampered JWE, unsupported header) are { decrypted: false }.
      decryptJwe: async (jwe, options) => {
        try {
          const { plaintext } = await compactDecrypt(jwe, o.decryptionKey, { keyManagementAlgorithms: ['ECDH-ES'], contentEncryptionAlgorithms: ENC_VALUES });
          return { decrypted: true, decryptionJwk: options!.jwk!, payload: utf8Decode(plaintext) };
        } catch {
          return { decrypted: false };
        }
      },
      encryptJwe: async (encryptor, data) => {
        if (encryptor.method !== 'jwk' || encryptor.alg !== 'ECDH-ES' || !ENC_VALUES.includes(encryptor.enc as JweEnc)) throw new TypeError('unsupported response encryption');
        const { kty, crv, x, y } = encryptor.publicJwk as unknown as EcPublicJwk;
        const jwe = await new CompactEncrypt(utf8Encode(data))
          .setProtectedHeader({ alg: 'ECDH-ES', enc: encryptor.enc, ...(encryptor.publicJwk.kid ? { kid: encryptor.publicJwk.kid } : {}) })
          .encrypt(await importJWK({ kty, crv, x, y }, 'ECDH-ES'));
        return { jwe, encryptionJwk: encryptor.publicJwk };
      },
    },
  });
}

export interface IssuerLibrary {
  credentialIssuerMetadata: Record<string, unknown>;
  authorizationServerMetadata: Record<string, unknown>;
  createOffer(input: { offerUri: string; configurationId: string; preAuthorizedCode: string; txCodeDescription: string }): Promise<{ offerUri: string; offer: CredentialOfferObject }>;
  parseCredentialRequest(input: { contentType: string; body: string }): Promise<ParsedCredentialRequest>;
  credentialResponse(credential: string, encryption: { jwk: EcPublicJwk & { alg: 'ECDH-ES' }; enc: JweEnc } | null): Promise<{ contentType: string; body: string }>;
}

export type ParsedCredentialRequest =
  | {
      ok: true;
      configurationId: string | undefined;
      /** Every proof the request carries, whatever its type, flattened; jwt proofs as strings. */
      jwtProofs: unknown[];
      otherProofs: boolean;
      /** The wallet's ephemeral key as received (not yet checked) and enc, or null. */
      responseEncryption: { jwk: unknown; enc: string } | null;
    }
  | { ok: false; error: string };

/** OAuth error codes of the library we pass on; any other failure is invalid_credential_request. */
const PASSED_ON = ['invalid_credential_request', 'unknown_credential_configuration', 'invalid_encryption_parameters'];

export function createIssuerLibrary(o: {
  issuerUri: string;
  display: Display;
  configurations: Record<string, ConfigurationMetadata>;
  requestEncryptionJwk: EcPublicJwk & { kid: string; alg: 'ECDH-ES'; use: 'enc' };
  decryptionKey: CryptoKey;
  hasher: Hasher;
  random: RandomSource;
}): IssuerLibrary {
  const issuer = libraryIssuer(o);
  const { issuerUri } = o;
  const authorizationServerMetadata = new Oauth2AuthorizationServer({ callbacks: {} as never }).createAuthorizationServerMetadata({
    issuer: issuerUri,
    token_endpoint: `${issuerUri}/token`,
    jwks_uri: `${issuerUri}/jwks`,
    grant_types_supported: [PRE_AUTHORIZED_GRANT],
    'pre-authorized_grant_anonymous_access_supported': true,
  });
  const credentialIssuer = issuer.createCredentialIssuerMetadata({
    credential_issuer: issuerUri,
    credential_endpoint: `${issuerUri}/credential`,
    nonce_endpoint: `${issuerUri}/nonce`,
    credential_request_encryption: { jwks: { keys: [{ ...o.requestEncryptionJwk }] }, enc_values_supported: ENC_VALUES, encryption_required: false },
    credential_response_encryption: { alg_values_supported: ['ECDH-ES'], enc_values_supported: ENC_VALUES, encryption_required: false },
    display: displayList(o.display),
    credential_configurations_supported: Object.fromEntries(
      Object.entries(o.configurations).map(([id, c]) => [
        id,
        {
          format: 'dc+sd-jwt',
          vct: c.vct,
          cryptographic_binding_methods_supported: ['jwk'],
          credential_signing_alg_values_supported: ['ES256'],
          proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } },
          credential_metadata: {
            display: displayList(c.display),
            claims: c.claims.map((claim) => ({ path: [claim.name], display: displayList(claim.display) })),
          },
        },
      ]),
    ),
  });
  const metadata: IssuerMetadataResult = {
    originalDraftVersion: Openid4vciVersion.V1,
    credentialIssuer,
    authorizationServers: [authorizationServerMetadata],
    knownCredentialConfigurations: issuer.getKnownCredentialConfigurationsSupported(credentialIssuer),
  };

  return {
    credentialIssuerMetadata: credentialIssuer,
    authorizationServerMetadata,

    async createOffer({ offerUri, configurationId, preAuthorizedCode, txCodeDescription }) {
      const { credentialOffer, credentialOfferObject } = await issuer.createCredentialOffer({
        issuerMetadata: metadata,
        credentialConfigurationIds: [configurationId],
        credentialOfferUri: offerUri,
        grants: {
          [PRE_AUTHORIZED_GRANT]: {
            'pre-authorized_code': preAuthorizedCode,
            tx_code: { input_mode: 'numeric', length: 6, description: txCodeDescription },
          },
        },
      });
      return { offerUri: credentialOffer, offer: credentialOfferObject };
    },

    async parseCredentialRequest({ contentType, body }) {
      let credentialRequest: unknown = body;
      if (!/^application\/jwt\s*(;|$)/i.test(contentType)) {
        try {
          credentialRequest = JSON.parse(body);
        } catch {
          return { ok: false, error: 'invalid_credential_request' };
        }
      }
      try {
        const parsed = await issuer.parseCredentialRequest({ issuerMetadata: metadata, contentType, credentialRequest: credentialRequest as never });
        const proofs = (parsed.proofs ?? {}) as Record<string, unknown[]>;
        const raw = parsed.credentialRequest as Record<string, unknown>;
        const enc = parsed.credentialResponseEncryption as { jwk: unknown; enc: string } | undefined;
        return {
          ok: true,
          configurationId: 'credentialConfigurationId' in parsed ? parsed.credentialConfigurationId : undefined,
          jwtProofs: proofs['jwt'] ?? [],
          otherProofs: Object.keys(proofs).some((k) => k !== 'jwt') || ('proof' in raw && 'proofs' in raw),
          responseEncryption: enc ? { jwk: enc.jwk, enc: enc.enc } : null,
        };
      } catch (e) {
        if (e instanceof Oauth2ServerErrorResponseError && e.status < 500) {
          const error = e.errorResponse.error;
          return { ok: false, error: PASSED_ON.includes(error) ? error : 'invalid_credential_request' };
        }
        throw e;
      }
    },

    async credentialResponse(credential, encryption) {
      const { credentialResponse, credentialResponseJwt } = await issuer.createCredentialResponse({
        credentialRequest: { credentialRequest: {} } as never,
        credentials: [{ credential }],
        ...(encryption ? { credentialResponseEncryption: { jwk: { ...encryption.jwk }, enc: encryption.enc } } : {}),
      });
      return credentialResponseJwt
        ? { contentType: 'application/jwt', body: credentialResponseJwt }
        : { contentType: 'application/json', body: JSON.stringify(credentialResponse) };
    },
  };
}
