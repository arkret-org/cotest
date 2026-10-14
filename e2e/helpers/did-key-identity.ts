// Real did:key identities for the MIMI provider fixture.

import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { ed25519PrivateKeySeedB64url, encodeEd25519PubkeyMultibase, rawEd25519PublicKey } from "./encoding";

export type DidKeyIdentity = {
  did: string;
  verificationMethod: string;
  publicKeyMultibase: string;
  signingSeedB64url: string;
  privateKey: KeyObject;
};

export function generateDidKeyIdentity(): DidKeyIdentity {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const multibase = encodeEd25519PubkeyMultibase(rawEd25519PublicKey(publicKey));
  const did = `did:key:${multibase}`;
  return {
    did,
    verificationMethod: `${did}#${multibase}`,
    publicKeyMultibase: multibase,
    signingSeedB64url: ed25519PrivateKeySeedB64url(privateKey),
    privateKey,
  };
}
