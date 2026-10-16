import { ethers, network } from "hardhat";

async function seedLocalRoles(contract: Awaited<ReturnType<typeof ethers.deployContract>>) {
  const signers = await ethers.getSigners();
  if (signers.length < 5) throw new Error("Local RBAC setup requires five Hardhat accounts.");
  const [owner, firstHolder, secondIssuer, secondHolder, thirdHolder] = signers;
  const accreditationHash = (address: string) => ethers.keccak256(ethers.toUtf8Bytes(`local-demo-accreditation-v1|${address.toLowerCase()}`));

  await (await contract.connect(secondIssuer).requestIssuerVerification(accreditationHash(secondIssuer.address))).wait();
  await (await contract.connect(owner).setIssuer(secondIssuer.address, true)).wait();

  console.log(`Local issuer 1 (contract owner): ${owner.address}`);
  console.log(`Local issuer 2: ${secondIssuer.address}`);
  console.log(`Local holder 1 (register manually): ${firstHolder.address}`);
  console.log(`Local holder 2 (register manually): ${secondHolder.address}`);
  console.log(`Local holder 3 (register manually): ${thirdHolder.address}`);
  console.log("No identity or credential was registered or minted. Run the holder and issuer flows manually in MetaMask.");
}

async function main() {
  const factory = await ethers.getContractFactory("VeriBindCredential");
  const localDemo = network.name === "localhost";
  const contract = await factory.deploy(localDemo ? 2 : 3);
  await contract.waitForDeployment();
  const contractAddress = await contract.getAddress();
  console.log(`VeriBindCredential deployed to ${contractAddress}`);
  if (localDemo) await seedLocalRoles(contract);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
