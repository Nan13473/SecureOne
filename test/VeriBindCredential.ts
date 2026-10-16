import { expect } from "chai";
import { ethers } from "hardhat";

describe("VeriBindCredential", function () {
  it("supports a two-issuer local demo quorum without auto-registering or minting", async function () {
    const [owner, holder, secondIssuer] = await ethers.getSigners();
    const contract = await ethers.deployContract("VeriBindCredential", [2]);
    await contract.waitForDeployment();

    expect(await contract.APPROVAL_THRESHOLD()).to.equal(2);
    expect(await contract.registeredHolderCount()).to.equal(0);
    expect(await contract.holderCredentialCount(holder.address)).to.equal(0);
    expect(await contract.roleOf(owner.address)).to.equal(2);

    await contract.connect(secondIssuer).requestIssuerVerification(ethers.keccak256(ethers.toUtf8Bytes("local-issuer-two")));
    await contract.connect(owner).setIssuer(secondIssuer.address, true);
    expect(await contract.roleOf(secondIssuer.address)).to.equal(2);
    expect(await contract.roleOf(holder.address)).to.equal(3);

    const identityHash = ethers.keccak256(ethers.toUtf8Bytes("manual-holder-registration"));
    const merkleRoot = ethers.keccak256(ethers.toUtf8Bytes("manual-credential-root"));
    await contract.connect(holder).registerIdentity(identityHash);
    await contract.connect(owner).proposeIssuance(holder.address, merkleRoot, ethers.ZeroHash, "", ethers.ZeroHash, ethers.ZeroHash, 1, 0);
    await expect(contract.connect(owner).finalizeIssuance(1)).to.be.revertedWithCustomError(contract, "ApprovalThresholdNotMet");
    await contract.connect(owner).approveIssuance(1);
    await contract.connect(secondIssuer).approveIssuance(1);
    await contract.connect(secondIssuer).finalizeIssuance(1);

    expect(await contract.holderCredentialAt(holder.address, 0)).to.equal(1);
    expect(await contract.credentialStatus(1)).to.equal(0);
  });

  it("requires identity registration and keeps lifecycle transitions append-only", async function () {
    const [owner, holder, otherHolder, issuerTwo, issuerThree] = await ethers.getSigners();
    const contract = await ethers.deployContract("VeriBindCredential", [3]);
    await contract.waitForDeployment();
    const docHash = ethers.keccak256(ethers.toUtf8Bytes("fixture-identity-v1"));
    const root = ethers.keccak256(ethers.toUtf8Bytes("certificate-root"));

    await expect(contract.connect(holder).registerIdentity(ethers.ZeroHash))
      .to.be.revertedWithCustomError(contract, "InvalidIdentityHash");
    await expect(contract.connect(owner).proposeIssuance(holder.address, root, ethers.ZeroHash, "bafy-demo", ethers.ZeroHash, ethers.ZeroHash, 1, 0))
      .to.be.revertedWithCustomError(contract, "IdentityNotRegistered");
    await contract.connect(holder).registerIdentity(docHash);
    expect(await contract.registeredHolderCount()).to.equal(1);
    expect(await contract.registeredHolderAt(0)).to.equal(holder.address);
    expect(await contract.holderCredentialCount(holder.address)).to.equal(0);
    await contract.connect(holder).registerIdentity(docHash);
    expect(await contract.registeredHolderCount()).to.equal(1);
    await expect(contract.connect(otherHolder).registerIdentity(docHash))
      .to.be.revertedWithCustomError(contract, "IdentityHashAlreadyRegistered");
    expect(await contract.roleOf(holder.address)).to.equal(1);
    expect(await contract.roleOf(issuerThree.address)).to.equal(3);
    await expect(contract.connect(owner).setIssuer(issuerTwo.address, true))
      .to.be.revertedWithCustomError(contract, "AccreditationNotSubmitted");
    await contract.connect(issuerTwo).requestIssuerVerification(ethers.keccak256(ethers.toUtf8Bytes("issuer-two-accreditation")));
    await contract.connect(issuerThree).requestIssuerVerification(ethers.keccak256(ethers.toUtf8Bytes("issuer-three-accreditation")));
    await contract.connect(owner).setIssuer(issuerTwo.address, true);
    await contract.connect(owner).setIssuer(issuerThree.address, true);
    await contract.connect(owner).proposeIssuance(holder.address, root, ethers.ZeroHash, "bafy-demo", ethers.ZeroHash, ethers.ZeroHash, 1, 0);
    await contract.connect(owner).approveIssuance(1);
    await contract.connect(issuerTwo).approveIssuance(1);
    await expect(contract.connect(owner).finalizeIssuance(1)).to.be.revertedWithCustomError(contract, "ApprovalThresholdNotMet");
    await contract.connect(issuerThree).approveIssuance(1);
    await contract.connect(owner).finalizeIssuance(1);
    expect(await contract.credentialRecipient(1)).to.equal(holder.address);
    expect(await contract.holderCredentialAt(holder.address, 0)).to.equal(1);
    expect(await contract.credentialMerkleRoot(1)).to.equal(root);
    expect(await contract.credentialPhotoHash(1)).to.equal(ethers.ZeroHash);
    expect(await contract.credentialIssuanceDigest(1)).to.equal(ethers.ZeroHash);
    expect(await contract.credentialStatus(1)).to.equal(0);
    expect((await contract.credentials(1)).status).to.equal(0);
    await contract.connect(holder).confirm(1);
    expect((await contract.credentials(1)).status).to.equal(1);
    await expect(contract.connect(holder).dispute(1)).to.be.revertedWithCustomError(contract, "InvalidStatus");
  });

  it("rejects transfers", async function () {
    const [owner, holder, other, thirdIssuer] = await ethers.getSigners();
    const contract = await ethers.deployContract("VeriBindCredential", [3]);
    await contract.waitForDeployment();
    await contract.connect(holder).registerIdentity(ethers.keccak256(ethers.toUtf8Bytes("id")));
    await contract.connect(other).requestIssuerVerification(ethers.keccak256(ethers.toUtf8Bytes("other-accreditation")));
    await contract.connect(thirdIssuer).requestIssuerVerification(ethers.keccak256(ethers.toUtf8Bytes("third-accreditation")));
    await contract.connect(owner).setIssuer(other.address, true);
    await contract.connect(owner).setIssuer(thirdIssuer.address, true);
    await contract.connect(owner).proposeIssuance(holder.address, ethers.ZeroHash, ethers.ZeroHash, "cid", ethers.ZeroHash, ethers.ZeroHash, 1, 0);
    await contract.connect(owner).approveIssuance(1);
    await contract.connect(other).approveIssuance(1);
    await contract.connect(thirdIssuer).approveIssuance(1);
    await contract.connect(owner).finalizeIssuance(1);
    await expect(contract.connect(holder).transferFrom(holder.address, other.address, 1))
      .to.be.revertedWithCustomError(contract, "Soulbound");
  });
});
