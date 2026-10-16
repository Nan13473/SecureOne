import { describe, expect, it } from "vitest";
import { buildCredentialPackage, canBuildCredential, findDuplicateCredential, issuanceDigestFor, parseCertificateUpload, validateCertificateRecord } from "./issuance";

const address = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const valid = {
  wallet_address: address,
  program: "Bachelor of Computer Science",
  name: "Ananya Rao",
  credential: "Bachelor of Computer Science",
  institution: "Northstar Institute",
  issued: "2026-09-14",
};

describe("issuer certificate data", () => {
  it("accepts valid JSON and CSV records", () => {
    expect(parseCertificateUpload(JSON.stringify(valid), "certificate.json", address).name).toBe("Ananya Rao");
    expect(parseCertificateUpload("wallet_address,program,name,credential,institution,issued\n" +
      `${address},BSc,Ananya Rao,BSc,Northstar Institute,2026-09-14`, "certificate.csv", address).program).toBe("BSc");
  });

  it("rejects malformed, missing, and mismatched data with specific errors", () => {
    expect(() => parseCertificateUpload("{", "certificate.json", address)).toThrow("Malformed JSON upload");
    expect(() => validateCertificateRecord({ ...valid, wallet_address: "" }, address)).toThrow("Required field wallet_address cannot be empty");
    expect(() => validateCertificateRecord({ ...valid, wallet_address: "0x0000000000000000000000000000000000000001" }, address)).toThrow("does not match");
    const missing = { ...valid } as Record<string, unknown>;
    delete missing.program;
    expect(() => validateCertificateRecord(missing, address)).toThrow("Missing required field: program");
  });

  it("builds commitments and clearly marks an unconfigured IPFS CID as a placeholder", async () => {
    const packageData = await buildCredentialPackage(validateCertificateRecord(valid, address));
    expect(packageData.merkleRoot).toMatch(/^0x[0-9a-f]{64}$/);
    expect(packageData.ciphertextHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(packageData.cid).toMatch(/^ipfs:\/\/placeholder\/demo-[0-9a-f]{32}$/);
    expect(packageData.cidIsPlaceholder).toBe(true);
    const secondPackage = await buildCredentialPackage(validateCertificateRecord(valid, address));
    expect(secondPackage.cid).not.toBe(packageData.cid);
  });

  it("gates building on DID and detects the same address/program digest", () => {
    expect(canBuildCredential(valid, address, false)).toBe(false);
    expect(canBuildCredential(valid, address, true)).toBe(true);
    expect(findDuplicateCredential(address, "Bachelor of Computer Science", [{
      tokenId: "7",
      issuanceDigest: issuanceDigestFor(address, "Bachelor of Computer Science"),
    }])).toBe("7");
  });
});
