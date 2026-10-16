import { describe, expect, it } from "vitest";
import { Wallet, getBytes } from "ethers";
import { buildMerkleProof, buildMerkleRoot, hashField } from "./merkle";
import { checkPresentation, checkVerificationChallenge, challengeDigest, presentationDigest, type VerificationChallenge, type VeribindPresentation } from "./presentation";

async function fixturePresentation(status: "Pending" | "Confirmed" = "Confirmed") {
  const signer = Wallet.createRandom();
  const values = ["Ananya Rao", "Bachelor of Computer Science", "Northstar Institute of Technology", "14 September 2026"];
  const names = ["name", "credential", "institution", "issued"];
  const leaves = await Promise.all(names.map((name, index) => hashField(1, name, values[index])));
  const unsigned = {
    type: "veribind-presentation" as const,
    version: 1 as const,
    chainId: 11155111,
    contractAddress: "0x0000000000000000000000000000000000000001",
    tokenId: "1",
    recipientAddress: signer.address,
    credentialStatus: "Confirmed" as const,
    disclosures: [{ fieldName: "name", fieldValue: values[0], fieldHash: leaves[0], fieldIndex: 0, merkleProof: await buildMerkleProof(leaves, 0) }],
    certificateMerkleRoot: await buildMerkleRoot(leaves),
    issuanceDigest: "0x" + "11".repeat(32),
    issuedAt: 1790035200,
    expiresAt: 0,
    nonce: "nonce-1",
  };
  const signedHash = presentationDigest(unsigned);
  const signature = await signer.signMessage(getBytes(signedHash));
  return { presentation: { ...unsigned, credentialStatus: status, signedHash, holderSignature: signature } as VeribindPresentation, signer };
}

describe("recipient presentations", () => {
  it("accepts a signed confirmed disclosure with a valid Merkle proof", async () => {
    const { presentation, signer } = await fixturePresentation();
    const result = await checkPresentation(presentation, {
      chainId: 11155111,
      contractAddress: presentation.contractAddress,
      recipientAddress: signer.address,
      tokenId: "1",
      status: "Confirmed",
      certificateMerkleRoot: presentation.certificateMerkleRoot,
      issuanceDigest: presentation.issuanceDigest,
      issuedAt: presentation.issuedAt,
      expiresAt: 0,
    });
    expect(result.valid).toBe(true);
  });

  it("rejects Pending credentials and altered disclosures", async () => {
    const pending = await fixturePresentation("Pending");
    const pendingResult = await checkPresentation(pending.presentation, {
      chainId: 11155111,
      contractAddress: pending.presentation.contractAddress,
      recipientAddress: pending.signer.address,
      tokenId: "1",
      status: "Pending",
      certificateMerkleRoot: pending.presentation.certificateMerkleRoot,
      issuanceDigest: pending.presentation.issuanceDigest,
      issuedAt: pending.presentation.issuedAt,
      expiresAt: 0,
    });
    expect(pendingResult).toEqual({ valid: false, reason: "Credential is Pending" });

    const valid = await fixturePresentation();
    valid.presentation.disclosures[0].fieldValue = "Changed value";
    const alteredResult = await checkPresentation(valid.presentation, {
      chainId: 11155111,
      contractAddress: valid.presentation.contractAddress,
      recipientAddress: valid.signer.address,
      tokenId: "1",
      status: "Confirmed",
      certificateMerkleRoot: valid.presentation.certificateMerkleRoot,
      issuanceDigest: valid.presentation.issuanceDigest,
      issuedAt: valid.presentation.issuedAt,
      expiresAt: 0,
    });
    expect(alteredResult.valid).toBe(false);
    expect(["Signed hash does not match presentation data", "Invalid holder signature", "Merkle proof failed for name"]).toContain(alteredResult.reason);
  });

  it("accepts only a matching fresh wallet challenge", async () => {
    const { presentation, signer } = await fixturePresentation();
    const challenge: VerificationChallenge = {
      challenge: "fresh-session-1",
      chainId: presentation.chainId,
      contractAddress: presentation.contractAddress,
      tokenId: presentation.tokenId,
      recipientAddress: signer.address,
      certificateMerkleRoot: presentation.certificateMerkleRoot,
      requestedFields: ["name"],
      issuedAt: Math.floor(Date.now() / 1000),
      expiresAt: Math.floor(Date.now() / 1000) + 120,
    };
    const challengeSignature = await signer.signMessage(getBytes(challengeDigest(challenge)));
    const challenged = { ...presentation, verificationChallenge: challenge, challengeSignature };
    expect(checkVerificationChallenge(challenged, challenge).valid).toBe(true);
    expect(checkVerificationChallenge(challenged, { ...challenge, challenge: "different-session" })).toEqual({ valid: false, reason: "Wallet challenge does not match this verification session" });
  });
});
