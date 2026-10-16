import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "dotenv/config";

const sepoliaRpcUrl = process.env.SEPOLIA_RPC_URL;
const rawDeployerPrivateKey = process.env.DEPLOYER_PRIVATE_KEY?.trim();
const deployerPrivateKey = rawDeployerPrivateKey
  ? rawDeployerPrivateKey.startsWith("0x") ? rawDeployerPrivateKey : `0x${rawDeployerPrivateKey}`
  : undefined;

if (deployerPrivateKey && !/^0x[0-9a-fA-F]{64}$/.test(deployerPrivateKey)) {
  throw new Error("DEPLOYER_PRIVATE_KEY must be a 32-byte hex private key (64 hex characters, optionally prefixed with 0x).");
}

const config: HardhatUserConfig = {
  solidity: "0.8.24",
  paths: { sources: "./contracts", tests: "./test", cache: "./.hardhat-cache", artifacts: "./artifacts" },
  networks: {
    hardhat: {},
    localhost: { url: "http://127.0.0.1:8545" },
    sepolia: {
      url: sepoliaRpcUrl || "https://sepolia.invalid",
      chainId: 11155111,
      accounts: deployerPrivateKey ? [deployerPrivateKey] : [],
    },
  },
};

export default config;
