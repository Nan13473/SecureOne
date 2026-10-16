import { getBytes, keccak256, toUtf8Bytes, verifyMessage, type BrowserProvider } from "ethers";
import { hashField, verifyMerkleProof, type MerkleProof } from "./merkle";

export type Disclosure = {
  fieldName: string;
  fieldValue: string;
  fieldHash: string;
  fieldIndex: number;
  merkleProof: MerkleProof;
};

export type VeribindPresentation = {
  type: "veribind-presentation";
  version: 1;
  chainId: number;
  contractAddress: string;
  tokenId: string;
  recipientAddress: string;
  credentialStatus: "Confirmed";
  disclosures: Disclosure[];
  certificateMerkleRoot: string;
  issuanceDigest: string;
  issuedAt: number;
  expiresAt: number;
  nonce: string;
  signedHash: string;
  holderSignature: string;
  verificationChallenge?: VerificationChallenge;
  challengeSignature?: string;
};

export type VerificationChallenge = {
  challenge: string;
  chainId: number;
  contractAddress: string;
  tokenId: string;
  recipientAddress: string;
  certificateMerkleRoot: string;
  requestedFields: string[];
  issuedAt: number;
  expiresAt: number;
};

export type PresentationCheck = {
  valid: boolean;
  reason?: string;
  recoveredSigner?: string;
};

export type OnChainPresentationContext = {
  chainId: number;
  contractAddress: string;
  recipientAddress: string;
  tokenId: string;
  status: "Pending" | "Confirmed" | "Disputed";
  certificateMerkleRoot: string;
  photoHash?: string;
  issuanceDigest: string;
  issuedAt: number;
  expiresAt: number;
};

type UnsignedPresentation = Omit<VeribindPresentation, "holderSignature" | "signedHash">;

export function canonicalPresentationPayload(presentation: UnsignedPresentation): string {
  return JSON.stringify({
    type: presentation.type,
    version: presentation.version,
    chainId: presentation.chainId,
    contractAddress: presentation.contractAddress.toLowerCase(),
    tokenId: presentation.tokenId,
    recipientAddress: presentation.recipientAddress.toLowerCase(),
    credentialStatus: presentation.credentialStatus,
    disclosures: presentation.disclosures,
    certificateMerkleRoot: presentation.certificateMerkleRoot,
    issuanceDigest: presentation.issuanceDigest,
    issuedAt: presentation.issuedAt,
    expiresAt: presentation.expiresAt,
    nonce: presentation.nonce,
    verificationChallenge: presentation.verificationChallenge ?? null,
  });
}

export function presentationDigest(presentation: UnsignedPresentation): string {
  return keccak256(toUtf8Bytes(`veribind-presentation-v1|${canonicalPresentationPayload(presentation)}`));
}

export async function signPresentation(
  provider: BrowserProvider,
  payload: UnsignedPresentation,
): Promise<VeribindPresentation> {
  const signer = await provider.getSigner();
  const signedHash = presentationDigest(payload);
  const signature = await signer.signMessage(getBytes(signedHash));
  return { ...payload, signedHash, holderSignature: signature };
}

export function canonicalChallengePayload(challenge: VerificationChallenge): string {
  return JSON.stringify({
    type: "veribind-wallet-challenge",
    version: 1,
    challenge: challenge.challenge,
    chainId: challenge.chainId,
    contractAddress: challenge.contractAddress.toLowerCase(),
    tokenId: challenge.tokenId,
    recipientAddress: challenge.recipientAddress.toLowerCase(),
    certificateMerkleRoot: challenge.certificateMerkleRoot,
    requestedFields: challenge.requestedFields,
    issuedAt: challenge.issuedAt,
    expiresAt: challenge.expiresAt,
  });
}

export function challengeDigest(challenge: VerificationChallenge): string {
  return keccak256(toUtf8Bytes(`veribind-wallet-challenge-v1|${canonicalChallengePayload(challenge)}`));
}

export async function signVerificationChallenge(provider: BrowserProvider, challenge: VerificationChallenge): Promise<string> {
  return (await provider.getSigner()).signMessage(getBytes(challengeDigest(challenge)));
}

export function checkVerificationChallenge(presentation: VeribindPresentation, challenge: VerificationChallenge): PresentationCheck {
  const signedChallenge = presentation.verificationChallenge;
  if (!signedChallenge || !presentation.challengeSignature) return { valid: false, reason: "Fresh wallet challenge signature is missing" };
  if (canonicalChallengePayload(signedChallenge) !== canonicalChallengePayload(challenge)) return { valid: false, reason: "Wallet challenge does not match this verification session" };
  if (challenge.expiresAt < Math.floor(Date.now() / 1000)) return { valid: false, reason: "Wallet challenge expired" };
  const recoveredSigner = verifyMessage(getBytes(challengeDigest(challenge)), presentation.challengeSignature);
  if (recoveredSigner.toLowerCase() !== challenge.recipientAddress.toLowerCase()) return { valid: false, reason: "Invalid fresh wallet challenge signature", recoveredSigner };
  return { valid: true, recoveredSigner };
}

export async function checkPresentation(
  presentation: VeribindPresentation,
  chain: OnChainPresentationContext,
): Promise<PresentationCheck> {
  if (presentation.type !== "veribind-presentation" || presentation.version !== 1) return { valid: false, reason: "Unsupported presentation schema" };
  if (presentation.chainId !== chain.chainId) return { valid: false, reason: "Wrong network" };
  if (presentation.contractAddress.toLowerCase() !== chain.contractAddress.toLowerCase()) return { valid: false, reason: "Unrecognized contract" };
  if (presentation.tokenId !== chain.tokenId) return { valid: false, reason: "Token ID mismatch" };
  if (chain.status !== "Confirmed") return { valid: false, reason: `Credential is ${chain.status}` };
  if (presentation.recipientAddress.toLowerCase() !== chain.recipientAddress.toLowerCase()) return { valid: false, reason: "Recipient mismatch" };
  if (presentation.certificateMerkleRoot !== chain.certificateMerkleRoot) return { valid: false, reason: "Merkle root mismatch" };
  if (presentation.issuanceDigest !== chain.issuanceDigest) return { valid: false, reason: "Issuance digest mismatch" };
  if (presentation.expiresAt > 0 && presentation.expiresAt < Math.floor(Date.now() / 1000)) return { valid: false, reason: "Presentation expired" };

  const { holderSignature, signedHash, ...unsigned } = presentation;
  const expectedSignedHash = presentationDigest(unsigned);
  if (signedHash !== expectedSignedHash) return { valid: false, reason: "Signed hash does not match presentation data" };
  const recoveredSigner = verifyMessage(getBytes(expectedSignedHash), holderSignature);
  if (recoveredSigner.toLowerCase() !== presentation.recipientAddress.toLowerCase()) return { valid: false, reason: "Invalid holder signature", recoveredSigner };

  for (const disclosure of presentation.disclosures) {
    if (disclosure.fieldName.toLowerCase() === "photo hash" && chain.photoHash && disclosure.fieldValue.toLowerCase() !== chain.photoHash.toLowerCase()) {
      return { valid: false, reason: "Photo commitment mismatch", recoveredSigner };
    }
    const leaf = await hashField(1, disclosure.fieldName, disclosure.fieldValue);
    if (disclosure.fieldHash !== leaf) return { valid: false, reason: `Field hash mismatch for ${disclosure.fieldName}`, recoveredSigner };
    const proofOk = await verifyMerkleProof(leaf, disclosure.merkleProof, chain.certificateMerkleRoot);
    if (!proofOk) return { valid: false, reason: `Merkle proof failed for ${disclosure.fieldName}`, recoveredSigner };
  }
  return { valid: true, recoveredSigner };
}

export function randomNonce(): string {
  const webCrypto = globalThis.crypto;
  if (!webCrypto?.getRandomValues) throw new Error("Web Crypto is unavailable. Open VeriBind through localhost or HTTPS.");
  const bytes = webCrypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
