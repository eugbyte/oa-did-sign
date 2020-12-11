import {
  WrappedDocument,
  SignedWrappedDocument,
  ProofType,
  utils,
  ProofPurpose,
  v2,
} from "@govtechsg/open-attestation";
import { SigningKey } from "src/types";
import { sign } from "../signer";

export const signDocument = async <T extends v2.OpenAttestationDocument>(
  document: SignedWrappedDocument<T> | WrappedDocument<T>,
  algorithm: string,
  publicKey: string,
  privateKey: string
): Promise<SignedWrappedDocument<T>> => {
  if (!utils.isWrappedV2Document(document)) throw new Error("Only v2 document is supported now");
  const merkleRoot = `0x${document.signature.merkleRoot}`;
  const signingKey: SigningKey = { private: privateKey, public: publicKey };
  const signature = await sign(algorithm, merkleRoot, signingKey);
  const proof = {
    type: ProofType.OpenAttestationSignature2018,
    created: new Date().toISOString(),
    proofPurpose: ProofPurpose.AssertionMethod,
    verificationMethod: publicKey,
    signature,
  };
  return utils.isSignedWrappedV2Document(document)
    ? { ...document, proof: [...document.proof, proof] }
    : { ...document, proof: [proof] };
};
