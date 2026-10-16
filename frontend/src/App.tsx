import { useEffect, useRef, useState } from "react";
import { BrowserProvider, Contract, ZeroHash, getBytes, keccak256, toUtf8Bytes, verifyMessage } from "ethers";
import QRCode from "qrcode";
import jsQR from "jsqr";
import { buildMerkleProof, buildMerkleRoot, hashField, verifyMerkleProof } from "./lib/merkle";
import { extractDocumentName, fingerprintDocumentText } from "./lib/identity";
import { checkPresentation, checkVerificationChallenge, randomNonce, signPresentation, signVerificationChallenge, type VerificationChallenge, type VeribindPresentation } from "./lib/presentation";
import { buildCredentialPackage, canBuildCredential, findDuplicateCredential, parseCertificateUpload, type CertificateRecord, type CredentialPackage, validateCertificateRecord } from "./lib/issuance";

type View = "identity" | "institution" | "holder" | "presentation" | "verify" | "debug";
type Status = "Pending" | "Confirmed" | "Disputed";
type Role = "holder" | "issuer" | "verifier";
type DemoHolder = { address: string; did: string; name: string; credential: string; institution: string; docHash: string; photoHash?: string; program?: string; issued?: string };
type ConsentStatus = "Pending" | "Approved" | "Rejected" | "Expired" | "Completed";
type ConsentRequest = {
  type: "veribind-verification-request";
  version: 1;
  requestId: string;
  organizationId: string;
  organizationName: string;
  requestedCredential: string;
  requestedFields: string[];
  purpose: string;
  expiresAt: number;
  nonce: string;
  status: ConsentStatus;
};
type ConsentResponse = Omit<ConsentRequest, "type" | "status"> & {
  type: "veribind-verification-response";
  status: "Approved";
  chainId: number;
  contractAddress: string;
  tokenId: string;
  recipientAddress: string;
  disclosures: { fieldName: string; fieldValue: string; fieldHash: string; fieldIndex: number; merkleProof: Awaited<ReturnType<typeof buildMerkleProof>> }[];
  certificateMerkleRoot: string;
  consentGranted: true;
  recipientSignature: string;
};

declare global {
  interface Window {
    ethereum?: { request: (args: { method: string }) => Promise<unknown> };
  }
}

const demoHolders: DemoHolder[] = [
  { address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", did: "did:veribind:holder-001", name: "Ananya Rao", credential: "Bachelor of Computer Science", institution: "Northstar Institute of Technology", docHash: "" },
  { address: "0x90F79bf6EB2c4f870365E785982E1f101E93b906", did: "did:veribind:holder-002", name: "Rohan Mehta", credential: "Master of Data Science", institution: "Eastbridge University", docHash: "" },
  { address: "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65", did: "did:veribind:holder-003", name: "Maya Iyer", credential: "Bachelor of Design", institution: "Harbor School of Arts", docHash: "" },
];

const identityRegistryAbi = [
  "function roleOf(address) view returns (uint8)",
  "function registerIdentity(bytes32 docHash)",
  "function registeredIdentity(address holder) view returns (bytes32)",
  "function registeredHolderCount() view returns (uint256)",
  "function registeredHolderAt(uint256 index) view returns (address)",
  "function proposeIssuance(address,bytes32,bytes32,string,bytes32,bytes32,uint8,uint64) returns (uint256)",
  "function approveIssuance(uint256)",
  "function finalizeIssuance(uint256) returns (uint256)",
  "function issuances(uint256) view returns (address holder,bytes32 merkleRoot,bytes32 photoHash,string cid,bytes32 ciphertextHash,bytes32 issuanceDigest,uint8 schemaVersion,uint64 expiresAt,uint8 approvals,bool finalized)",
  "function hasApproved(uint256,address) view returns (bool)",
  "function APPROVAL_THRESHOLD() view returns (uint8)",
  "event IssuanceProposed(uint256 indexed issuanceId,address indexed holder,bytes32 merkleRoot,string cid)",
];

function holderForAddress(address: string): DemoHolder {
  return demoHolders.find((holder) => holder.address.toLowerCase() === address.toLowerCase()) ?? {
    address,
    did: `did:veribind:${address.slice(0, 10).toLowerCase()}`,
    name: "Unregistered wallet holder",
    credential: "No credential registered",
    institution: "Awaiting verified issuer",
    docHash: "",
  };
}

function isRealWalletAddress(address: string): boolean {
  return /^0x[0-9a-f]{40}$/i.test(address);
}

function toBytes32Fingerprint(fingerprint: string): string {
  const normalized = fingerprint.replace(/^0x/i, "");
  if (!/^[0-9a-f]{64}$/i.test(normalized)) throw new Error("Document hash must be a SHA-256 fingerprint.");
  return `0x${normalized}`;
}

function profileForAddress(profiles: Record<string, DemoHolder>, address: string): DemoHolder {
  const profileAddress = Object.keys(profiles).find((candidate) => candidate.toLowerCase() === address.toLowerCase());
  return profileAddress ? profiles[profileAddress] : holderForAddress(address);
}

function photoHashForHolder(holder: DemoHolder): string {
  return holder.photoHash ?? keccak256(toUtf8Bytes(`veribind-photo-v1|${holder.did}`));
}

async function detectWalletRole(provider: BrowserProvider, address: string): Promise<Role> {
  const contractAddress = import.meta.env.VITE_VERIBIND_CONTRACT_ADDRESS;
  if (!contractAddress || !isRealWalletAddress(contractAddress) || /^0x0{40}$/i.test(contractAddress)) {
    return roleForAddress(address);
  }

  const network = await provider.getNetwork();
  const expectedChainId = Number(import.meta.env.VITE_OFFICIAL_CHAIN_ID || 11155111);
  if (Number(network.chainId) !== expectedChainId) {
    throw new Error(`Switch MetaMask to chain ${expectedChainId} to detect your issuer role.`);
  }

  const contract = new Contract(contractAddress, identityRegistryAbi, provider);
  const onChainRole = Number(await contract.roleOf(address));
  if (onChainRole === 2) return "issuer";
  if (onChainRole === 1) return "holder";
  return "verifier";
}

function App() {
  const [session, setSession] = useState<{
    role: Role;
    address: string;
  } | null>(null);
  const [darkMode, setDarkMode] = useState(true);
  const [view, setView] = useState<View>("identity");
  const [registeredDids, setRegisteredDids] = useState<string[]>([]);
  const [identityProfiles, setIdentityProfiles] = useState<Record<string, DemoHolder>>({});
  const [documentOwners, setDocumentOwners] = useState<Record<string, string>>({});
  const [issuerRequested, setIssuerRequested] = useState(false);
  const [issuerVerified, setIssuerVerified] = useState(false);
  const [selectedHolderAddress, setSelectedHolderAddress] = useState(demoHolders[0].address);
  const [approved, setApproved] = useState(3);
  const [minted, setMinted] = useState(false);
  const [status, setStatus] = useState<Status>("Pending");
  const [chainCredential, setChainCredential] = useState<{ tokenId: string; merkleRoot: string; issuanceDigest: string; issuedAt: number; expiresAt: number } | null>(null);
  const [credentialRefreshVersion, setCredentialRefreshVersion] = useState(0);
  const [chainIssuance, setChainIssuance] = useState<{ id: string; approvals: number; threshold: number; finalized: boolean; approvedByMe: boolean; merkleRoot: string; expiresAt: number } | null>(null);
  const [issuanceRefreshVersion, setIssuanceRefreshVersion] = useState(0);
  const [issuanceBusy, setIssuanceBusy] = useState(false);
  const [preparedPackage, setPreparedPackage] = useState<CredentialPackage | null>(null);
  const [lastTransactionHash, setLastTransactionHash] = useState("");
  const [field, setField] = useState("Credential");
  const [proofRequested, setProofRequested] = useState(false);
  const [proofRequestRecipient, setProofRequestRecipient] = useState("");
  const [proofSent, setProofSent] = useState(false);
  const [proofDenied, setProofDenied] = useState(false);
  const [registryError, setRegistryError] = useState("");
  const [consentRequest, setConsentRequest] = useState<ConsentRequest | null>(null);
  const [consentResponse, setConsentResponse] = useState<ConsentResponse | null>(null);
  const [consentError, setConsentError] = useState("");

  const registered = registeredDids.some((address) => address.toLowerCase() === selectedHolderAddress.toLowerCase());

  useEffect(() => {
    const contractAddress = import.meta.env.VITE_VERIBIND_CONTRACT_ADDRESS;
    if (!session || !isRealWalletAddress(session.address) || !window.ethereum || !contractAddress || !isRealWalletAddress(contractAddress) || /^0x0{40}$/i.test(contractAddress)) return;
    let active = true;
    const syncRegistry = async () => {
      const provider = new BrowserProvider(window.ethereum as never);
      const network = await provider.getNetwork();
      const expectedChainId = Number(import.meta.env.VITE_OFFICIAL_CHAIN_ID || 11155111);
      if (Number(network.chainId) !== expectedChainId) throw new Error(`Switch MetaMask to chain ${expectedChainId} to load registered identities.`);
      const contract = new Contract(contractAddress, identityRegistryAbi, provider);
      let addresses: string[] = [];
      if (session.role === "issuer") {
        const count = Number(await contract.registeredHolderCount());
        if (!Number.isSafeInteger(count)) throw new Error("Registered identity count is too large to load.");
        addresses = await Promise.all(Array.from({ length: count }, (_, index) => contract.registeredHolderAt(index) as Promise<string>));
      } else if (session.role === "holder") {
        const identityHash = String(await contract.registeredIdentity(session.address));
        if (!/^0x0{64}$/i.test(identityHash)) addresses = [session.address];
      }
      const profiles = await Promise.all(addresses.map(async (address) => ({
        address,
        docHash: String(await contract.registeredIdentity(address)),
      })));
      if (!active) return;
      setRegistryError("");
      setRegisteredDids((current) => [...current, ...addresses.filter((address) => !current.some((existing) => existing.toLowerCase() === address.toLowerCase()))]);
      setIdentityProfiles((current) => {
        const next = { ...current };
        for (const profile of profiles) {
          const existingAddress = Object.keys(next).find((address) => address.toLowerCase() === profile.address.toLowerCase()) ?? profile.address;
          next[existingAddress] = { ...profileForAddress(next, profile.address), docHash: profile.docHash };
        }
        return next;
      });
      if (session.role === "issuer" && addresses.length) {
        setSelectedHolderAddress((current) => addresses.some((address) => address.toLowerCase() === current.toLowerCase()) ? current : addresses[addresses.length - 1]);
      }
    };
    void syncRegistry().catch((reason) => {
      if (active) setRegistryError(reason instanceof Error ? reason.message : "Unable to load registered identities.");
    });
    const interval = window.setInterval(() => {
      void syncRegistry().catch((reason) => {
        if (active) setRegistryError(reason instanceof Error ? reason.message : "Unable to refresh registered identities.");
      });
    }, 5000);
    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, [session]);

  useEffect(() => {
    const contractAddress = import.meta.env.VITE_VERIBIND_CONTRACT_ADDRESS;
    if (!session || !isRealWalletAddress(selectedHolderAddress) || !window.ethereum || !contractAddress || !isRealWalletAddress(contractAddress) || /^0x0{40}$/i.test(contractAddress)) {
      setChainCredential(null);
      return;
    }
    let active = true;
    const syncCredential = async () => {
      try {
        const provider = new BrowserProvider(window.ethereum as never);
        const network = await provider.getNetwork();
        if (Number(network.chainId) !== presentationChainId) throw new Error(`Switch MetaMask to chain ${presentationChainId} to load credential status.`);
        const contract = new Contract(contractAddress, credentialReadAbi, provider);
        const count = Number(await contract.holderCredentialCount(selectedHolderAddress));
        if (!Number.isSafeInteger(count)) throw new Error("Credential count is too large to load.");
        if (!count) {
          if (active) {
            setChainCredential(null);
            setMinted(false);
            setStatus("Pending");
          }
          return;
        }
        const tokenId = String(await contract.holderCredentialAt(selectedHolderAddress, count - 1));
        const statusNames = ["Pending", "Confirmed", "Disputed"] as const;
        const statusFromChain = statusNames[Number(await contract.credentialStatus(tokenId))] ?? "Disputed";
        const credential = {
          tokenId,
          merkleRoot: String(await contract.credentialMerkleRoot(tokenId)),
          issuanceDigest: String(await contract.credentialIssuanceDigest(tokenId)),
          issuedAt: Number(await contract.credentialIssuedAt(tokenId)),
          expiresAt: Number(await contract.credentialExpiresAt(tokenId)),
        };
        if (active) {
          setChainCredential(credential);
          setMinted(true);
          setStatus(statusFromChain);
          setRegistryError("");
        }
      } catch (reason) {
        if (active) setRegistryError(reason instanceof Error ? reason.message : "Unable to read credential state from the contract.");
      }
    };
    void syncCredential();
    const interval = window.setInterval(() => void syncCredential(), 5000);
    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, [session, selectedHolderAddress, credentialRefreshVersion]);

  useEffect(() => {
    const contractAddress = import.meta.env.VITE_VERIBIND_CONTRACT_ADDRESS;
    if (!session || session.role !== "issuer" || !isRealWalletAddress(session.address) || !isRealWalletAddress(selectedHolderAddress) || !window.ethereum || !contractAddress || !isRealWalletAddress(contractAddress) || /^0x0{40}$/i.test(contractAddress)) {
      setChainIssuance(null);
      return;
    }
    let active = true;
    const syncIssuance = async () => {
      try {
        const provider = new BrowserProvider(window.ethereum as never);
        const network = await provider.getNetwork();
        if (Number(network.chainId) !== presentationChainId) throw new Error(`Switch MetaMask to chain ${presentationChainId} to load issuance approvals.`);
        const contract = new Contract(contractAddress, identityRegistryAbi, provider);
        const latestBlock = await provider.getBlockNumber();
        const configuredDeploymentBlock = Number(import.meta.env.VITE_VERIBIND_DEPLOYMENT_BLOCK || 0);
        const maxLogRange = 100;
        const configuredFromBlock = configuredDeploymentBlock > 0
          ? configuredDeploymentBlock
          : latestBlock - maxLogRange;
        const fromBlock = Math.max(0, Math.max(configuredFromBlock, latestBlock - maxLogRange));
        const events = [];
        const filter = contract.filters.IssuanceProposed(null, selectedHolderAddress);
        for (let chunkStart = fromBlock; chunkStart <= latestBlock; chunkStart += 10) {
          const chunkEnd = Math.min(latestBlock, chunkStart + 9);
          events.push(...await contract.queryFilter(filter, chunkStart, chunkEnd));
        }
        const threshold = Number(await contract.APPROVAL_THRESHOLD());
        let latest = null;
        for (const event of [...events].reverse()) {
          if (!("args" in event)) continue;
          const args = event.args as readonly unknown[];
          const issuanceId = String(args[0]);
          const issuance = await contract.issuances(issuanceId);
          const finalized = Boolean(issuance.finalized ?? issuance[9]);
          if (!finalized) {
            latest = {
              id: issuanceId,
              approvals: Number(issuance.approvals ?? issuance[8]),
              threshold,
              finalized,
              approvedByMe: Boolean(await contract.hasApproved(issuanceId, session.address)),
              merkleRoot: String(issuance.merkleRoot ?? issuance[1]),
              expiresAt: Number(issuance.expiresAt ?? issuance[7]),
            };
            break;
          }
        }
        if (active) {
          setChainIssuance(latest);
          setRegistryError("");
        }
      } catch (reason) {
        if (active) setRegistryError(reason instanceof Error ? reason.message : "Unable to load on-chain issuer approvals.");
      }
    };
    void syncIssuance();
    const interval = window.setInterval(() => void syncIssuance(), 5000);
    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, [session, selectedHolderAddress, issuanceRefreshVersion]);

  const submitIssuanceAction = async (action: "propose" | "approve" | "finalize") => {
    if (!session || session.role !== "issuer" || !isRealWalletAddress(session.address)) {
      throw new Error("Connect an authorized issuer wallet in MetaMask.");
    }
    if (!window.ethereum) throw new Error("MetaMask is required for issuer transactions.");
    setIssuanceBusy(true);
    setRegistryError("");
    try {
      const provider = new BrowserProvider(window.ethereum as never);
      const network = await provider.getNetwork();
      if (Number(network.chainId) !== presentationChainId) throw new Error(`Switch MetaMask to chain ${presentationChainId}.`);
      const signer = await provider.getSigner();
      if ((await signer.getAddress()).toLowerCase() !== session.address.toLowerCase()) throw new Error("The active MetaMask account changed. Reconnect the issuer wallet.");
      const contract = new Contract(presentationContract, identityRegistryAbi, signer);
      if (Number(await contract.roleOf(session.address)) !== 2) throw new Error("This wallet is not authorized as an issuer on this contract.");

      let transaction;
      if (action === "propose") {
        if (!preparedPackage || preparedPackage.walletAddress.toLowerCase() !== selectedHolderAddress.toLowerCase()) {
          throw new Error("Build and review the credential package before proposing issuance.");
        }
        transaction = await contract.proposeIssuance(
          preparedPackage.walletAddress,
          preparedPackage.merkleRoot,
          preparedPackage.photoHash,
          preparedPackage.cid,
          preparedPackage.ciphertextHash,
          preparedPackage.issuanceDigest,
          preparedPackage.schemaVersion,
          preparedPackage.expiresAt,
        );
      } else {
        if (!chainIssuance) throw new Error("There is no pending issuance for this holder.");
        transaction = action === "approve"
          ? await contract.approveIssuance(chainIssuance.id)
          : await contract.finalizeIssuance(chainIssuance.id);
      }
      setLastTransactionHash(transaction.hash);
      await transaction.wait();
      setIssuanceRefreshVersion((version) => version + 1);
      setCredentialRefreshVersion((version) => version + 1);
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "Issuer transaction failed.";
      setRegistryError(message);
      throw new Error(message);
    } finally {
      setIssuanceBusy(false);
    }
  };

  const changeCredentialStatus = async (nextStatus: Status) => {
    if (!chainCredential || !session || !isRealWalletAddress(session.address)) {
      setStatus(nextStatus);
      return;
    }
    if (session.address.toLowerCase() !== selectedHolderAddress.toLowerCase()) {
      setRegistryError("Only the wallet that owns this credential can change its status.");
      return;
    }
    if (!window.ethereum) {
      setRegistryError("Connect MetaMask to change the on-chain credential status.");
      return;
    }
    try {
      const provider = new BrowserProvider(window.ethereum as never);
      const network = await provider.getNetwork();
      if (Number(network.chainId) !== presentationChainId) throw new Error(`Switch MetaMask to chain ${presentationChainId}.`);
      const signer = await provider.getSigner();
      const contract = new Contract(presentationContract, [...credentialReadAbi, "function confirm(uint256)", "function dispute(uint256)"], signer);
      const transaction = nextStatus === "Confirmed"
        ? await contract.confirm(chainCredential.tokenId)
        : await contract.dispute(chainCredential.tokenId);
      await transaction.wait();
      setCredentialRefreshVersion((version) => version + 1);
    } catch (reason) {
      setRegistryError(reason instanceof Error ? reason.message : "Credential status transaction failed.");
    }
  };
  const selectHolder = (address: string) => {
    setSelectedHolderAddress(address);
    setMinted(false);
    setStatus("Pending");
    setApproved(3);
    setProofRequested(false);
    setProofSent(false);
    setProofDenied(false);
    setPreparedPackage(null);
  };

  const checkStudentDid = async (address: string, demoMode = false): Promise<{ registered: boolean; source: "on-chain" | "demo-local" }> => {
    if (!isRealWalletAddress(address)) throw new Error("Enter a valid Ethereum wallet address.");
    const contractAddress = import.meta.env.VITE_VERIBIND_CONTRACT_ADDRESS;
    if (demoMode) {
      return { registered: demoHolders.some((candidate) => candidate.address.toLowerCase() === address.toLowerCase()) || registeredDids.some((candidate) => candidate.toLowerCase() === address.toLowerCase()), source: "demo-local" };
    }
    if (!window.ethereum || !contractAddress || !isRealWalletAddress(contractAddress) || /^0x0{40}$/i.test(contractAddress)) {
      return { registered: registeredDids.some((candidate) => candidate.toLowerCase() === address.toLowerCase()), source: "demo-local" };
    }
    const provider = new BrowserProvider(window.ethereum as never);
    const network = await provider.getNetwork();
    if (Number(network.chainId) !== presentationChainId) throw new Error(`Switch MetaMask to chain ${presentationChainId} to check the DID.`);
    const contract = new Contract(contractAddress, identityRegistryAbi, provider);
    const identityHash = String(await contract.registeredIdentity(address));
    return { registered: !/^0x0{64}$/i.test(identityHash), source: "on-chain" };
  };

  const checkProgramDuplicate = async (address: string, program: string): Promise<{ duplicate: boolean; source: "on-chain" | "demo-local"; tokenId?: string }> => {
    const contractAddress = import.meta.env.VITE_VERIBIND_CONTRACT_ADDRESS;
    if (!window.ethereum || !contractAddress || !isRealWalletAddress(contractAddress) || /^0x0{40}$/i.test(contractAddress)) {
      return { duplicate: false, source: "demo-local" };
    }
    const provider = new BrowserProvider(window.ethereum as never);
    const network = await provider.getNetwork();
    if (Number(network.chainId) !== presentationChainId) throw new Error(`Switch MetaMask to chain ${presentationChainId} to check duplicate credentials.`);
    const contract = new Contract(contractAddress, credentialReadAbi, provider);
    const count = Number(await contract.holderCredentialCount(address));
    const credentials: { tokenId: string; issuanceDigest: string }[] = [];
    for (let index = 0; index < count; index += 1) {
      const tokenId = String(await contract.holderCredentialAt(address, index));
      const digest = String(await contract.credentialIssuanceDigest(tokenId));
      credentials.push({ tokenId, issuanceDigest: digest });
    }
    const duplicateTokenId = findDuplicateCredential(address, program, credentials);
    return duplicateTokenId ? { duplicate: true, source: "on-chain", tokenId: duplicateTokenId } : { duplicate: false, source: "on-chain" };
  };

  if (!session)
    return (
      <div className="app-shell dark">
        <WalletLogin
          onConnect={(role, address) => {
            setSession({ role, address });
            const fixtureHolder = demoHolders.find((holder) => holder.address.toLowerCase() === address.toLowerCase());
            const latestRegisteredDid = registeredDids[registeredDids.length - 1];
            setSelectedHolderAddress(fixtureHolder?.address ?? (role === "issuer" ? latestRegisteredDid ?? demoHolders[0].address : isRealWalletAddress(address) ? address : demoHolders[0].address));
            setIssuerVerified(role === "issuer");
            setView(role === "issuer" ? "institution" : "identity");
          }}
        />
      </div>
    );

  const allNav: [View, string, string][] = [
    ["identity", "Identity", "01"],
    ["institution", "Issue", "02"],
    ["holder", "Review", "03"],
    ["presentation", "Present", "04"],
    ["verify", "Verify", "05"],
    ["debug", "Debug", "06"],
  ];
  const nav = allNav.filter(([key]) =>
    key === "debug" ||
    key === "identity" ||
    key === "verify" ||
    (registered && (key === "holder" || key === "presentation")) ||
    (issuerVerified && key === "institution")
  );
  const selectedHolder = identityProfiles[selectedHolderAddress] ?? holderForAddress(selectedHolderAddress);
  const demoHolderAddresses = new Set(demoHolders.map((candidate) => candidate.address.toLowerCase()));
  const issuerRecipients = [
    ...demoHolders,
            ...registeredDids
              .filter((address) => !demoHolderAddresses.has(address.toLowerCase()))
              .map((address) => profileForAddress(identityProfiles, address)),
  ];
  const title =
    view === "identity"
      ? "Register your identity"
      : view === "institution"
      ? "Issue a credential"
      : view === "holder"
      ? "Review your credential"
      : view === "presentation"
      ? "Create a verification QR"
      : view === "verify"
      ? "Verify a credential"
      : "Flow debugger";
  const eyebrow =
    view === "identity"
      ? "YOUR IDENTITY"
      : view === "institution"
      ? "INSTITUTION"
      : view === "holder"
      ? "YOUR CREDENTIAL"
      : view === "presentation"
      ? "YOUR WALLET"
      : view === "verify"
      ? "PUBLIC CHECK"
      : "DEVELOPER MODE";

  return (
    <div className={`app-shell ${darkMode ? "dark" : ""}`}>
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">V</span>
          <span>veribind</span>
        </div>
        <nav>
          {nav.map(([key, label, number]) => (
            <button
              className={`nav-item ${view === key ? "active" : ""}`}
              onClick={() => setView(key)}
              key={key}
            >
              <span className="nav-number">{number}</span>
              {label}
            </button>
          ))}
        </nav>
      </aside>
      <main className="main-content">
        <header className="topbar">
          <div>
            <span className="eyebrow">{eyebrow}</span>
            <h1>{title}</h1>
          </div>
          <div className="header-meta">
            <span className="chain-pill">
              <span className="green-dot" /> {session.role} ·{" "}
              {shortAddress(session.address)}
            </span>
            <button
              className="theme-button"
              onClick={() => setDarkMode((value) => !value)}
              aria-label="Toggle dark theme"
            >
              {darkMode ? "Light" : "Dark"}
            </button>
            <button className="session-button" onClick={() => setSession(null)}>
              Switch wallet
            </button>
          </div>
        </header>
        {registryError && <p className="presentation-error" role="alert">{registryError}</p>}
        {view === "identity" && (
          <Identity
            registered={registered}
            holder={selectedHolder}
            issuerRequested={issuerRequested}
            issuerVerified={issuerVerified}
            onRequestIssuer={() => setIssuerRequested(true)}
            onVerifyIssuer={() => {
              setIssuerVerified(true);
              setView("institution");
            }}
            onRegister={async (fingerprint, record) => {
              const existingOwner = documentOwners[fingerprint];
              if (existingOwner && existingOwner.toLowerCase() !== selectedHolderAddress.toLowerCase()) return false;

              if (isRealWalletAddress(selectedHolderAddress)) {
                const contractAddress = import.meta.env.VITE_VERIBIND_CONTRACT_ADDRESS;
                if (!window.ethereum) throw new Error("Connect the holder wallet to register this identity.");
                if (!contractAddress || !isRealWalletAddress(contractAddress) || /^0x0{40}$/i.test(contractAddress)) {
                  throw new Error("Configure VITE_VERIBIND_CONTRACT_ADDRESS before registering on-chain.");
                }
                const provider = new BrowserProvider(window.ethereum as never);
                const network = await provider.getNetwork();
                const expectedChainId = Number(import.meta.env.VITE_OFFICIAL_CHAIN_ID || 11155111);
                if (Number(network.chainId) !== expectedChainId) throw new Error(`Switch MetaMask to chain ${expectedChainId} before registering.`);
                const accounts = (await provider.send("eth_accounts", [])) as string[];
                if (accounts[0]?.toLowerCase() !== selectedHolderAddress.toLowerCase()) throw new Error("The connected MetaMask account does not match this identity.");
                const signer = await provider.getSigner();
                const contract = new Contract(contractAddress, identityRegistryAbi, signer);
                const transaction = await contract.registerIdentity(toBytes32Fingerprint(fingerprint));
                await transaction.wait();
              }

              setDocumentOwners((current) => ({ ...current, [fingerprint]: selectedHolderAddress }));
              setIdentityProfiles((current) => ({ ...current, [selectedHolderAddress]: record }));
              setRegisteredDids((current) => current.some((address) => address.toLowerCase() === selectedHolderAddress.toLowerCase()) ? current : [...current, selectedHolderAddress]);
              if (isRealWalletAddress(selectedHolderAddress)) setSession((current) => current ? { ...current, role: "holder" } : current);
              setView("holder");
              return true;
            }}
          />
        )}
        {view === "institution" && (
          <Institution
            chainBacked={isRealWalletAddress(session.address) && isRealWalletAddress(presentationContract) && !/^0x0{40}$/i.test(presentationContract)}
            chainCredential={chainCredential}
            status={status}
            chainIssuance={chainIssuance}
            issuanceBusy={issuanceBusy}
            onIssuerAction={submitIssuanceAction}
            minted={minted}
            setMinted={setMinted}
            onCheckDid={checkStudentDid}
            onCheckDuplicate={checkProgramDuplicate}
            onPrepare={(packageData, address) => {
              setPreparedPackage(packageData);
              setSelectedHolderAddress(address);
              setIdentityProfiles((current) => ({ ...current, [address]: { ...profileForAddress(current, address), address, name: packageData.fields.find(([name]) => name === "name")?.[1] ?? "Credential holder", program: packageData.program, credential: packageData.fields.find(([name]) => name === "credential")?.[1] ?? packageData.program, institution: packageData.fields.find(([name]) => name === "institution")?.[1] ?? "Institution", issued: packageData.fields.find(([name]) => name === "issued")?.[1], photoHash: packageData.fields.some(([name]) => name === "photo hash") ? packageData.photoHash : undefined, docHash: "" } }));
            }}
            transactionHash={lastTransactionHash}
          />
        )}
        {view === "holder" && (
          <Holder
            minted={minted}
            status={status}
            setStatus={(nextStatus) => { void changeCredentialStatus(nextStatus); }}
            field={field}
            proofRequested={proofRequested && proofRequestRecipient.toLowerCase() === session.address.toLowerCase()}
            proofSent={proofSent}
            proofDenied={proofDenied}
            holder={selectedHolder}
            chainCredential={chainCredential}
            consentRequest={consentRequest}
            consentError={consentError}
            onConsentDecision={async (decision) => {
              setConsentError("");
              if (decision === "reject") {
                setConsentRequest((current) => current ? { ...current, status: "Rejected" } : current);
                return;
              }
              if (!window.ethereum) {
                setConsentError("Connect the holder wallet to sign consent.");
                return;
              }
              try {
                const provider = new BrowserProvider(window.ethereum as never);
                const accounts = (await provider.send("eth_accounts", [])) as string[];
                if (!accounts[0]) throw new Error("Connect the holder wallet to sign consent.");
                if (isRealWalletAddress(selectedHolder.address) && accounts[0].toLowerCase() !== selectedHolder.address.toLowerCase()) throw new Error("Connected wallet does not match the selected holder.");
                const response = await signConsentResponse(provider, consentRequest, selectedHolder, accounts[0]);
                setConsentResponse(response);
                setConsentRequest((current) => current ? { ...current, status: "Approved" } : current);
              } catch (reason) {
                setConsentError(reason instanceof Error ? reason.message : "Consent signature was cancelled.");
              }
            }}
            setProofSent={setProofSent}
            setProofDenied={setProofDenied}
          />
        )}
        {view === "presentation" && (
          <Presentation
            minted={minted}
            status={status}
            holder={selectedHolder}
            chainCredential={chainCredential}
            recipientAddress={session.address}
            field={field}
            consentRequest={consentRequest}
            consentResponse={consentResponse}
            onCreateConsentRequest={(request) => {
              setConsentError("");
              setConsentResponse(null);
              setConsentRequest(request);
            }}
            onWalletConnected={(address) => setSession({ ...session, address })}
          />
        )}
        {view === "verify" && (
          <Verifier
            minted={minted}
            status={status}
            field={field}
            setField={setField}
            proofRequested={proofRequested}
            setProofRequested={setProofRequested}
            proofSent={proofSent}
            setProofSent={setProofSent}
            proofDenied={proofDenied}
            setProofDenied={setProofDenied}
            holder={selectedHolder}
            proofRequestRecipient={proofRequestRecipient}
            setProofRequestRecipient={setProofRequestRecipient}
          />
        )}
        {view === "debug" && (
          <Debug
            status={status}
            registered={registered}
            approved={approved}
            minted={minted}
            proofRequested={proofRequested}
            proofSent={proofSent}
            proofDenied={proofDenied}
            field={field}
            walletAddress={session.address}
            chainCredential={chainCredential}
          />
        )}
      </main>
    </div>
  );
}

function WalletLogin({
  onConnect,
}: {
  onConnect: (role: Role, address: string) => void;
}) {
  const [error, setError] = useState("");
  const isMobile = /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
  const openMetaMaskMobile = () => {
    const dappUrl = `${window.location.host}${window.location.pathname}${window.location.search}`;
    window.location.href = `https://metamask.app.link/dapp/${dappUrl}`;
  };
  const connect = async () => {
    setError("");
    if (!window.ethereum) return setError("MetaMask was not detected. Install it or use a fixture wallet for the demo.");
    try {
      const provider = new BrowserProvider(window.ethereum as never);
      const accounts = (await provider.send("eth_requestAccounts", [])) as string[];
      if (accounts[0]) onConnect(await detectWalletRole(provider, accounts[0]), accounts[0]);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Wallet connection was cancelled.");
    }
  };
  return (
    <main className="developer-login">
      <div className="login-mark">V</div>
      <span className="eyebrow">VERIBIND / WALLET ACCESS</span>
      <h1>Connect your wallet</h1>
      <p>
        Your wallet is your login. VeriBind uses the connected address and
        on-chain permissions to load the right workspace.
      </p>
      <button className="primary-action wallet-connect" onClick={connect}>
        Connect MetaMask <span>→</span>
      </button>
      {isMobile && !window.ethereum && (
        <button className="secondary-action mobile-wallet-button" onClick={openMetaMaskMobile}>
          Open in MetaMask Mobile <span>↗</span>
        </button>
      )}
      {error && <p className="presentation-error">{error}</p>}
      <div className="demo-wallets">
        <span className="eyebrow">LOCAL FIXTURE WALLETS</span>
        {demoHolders.map((holder, index) => (
          <button key={holder.address} onClick={() => onConnect("holder", holder.address)}>
            Holder wallet {String(index + 1).padStart(2, "0")} <small>{holder.did}</small>
          </button>
        ))}
        <button onClick={() => onConnect("issuer", "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")}>
          Issuer wallet 1 <small>Hardhat account 0 · owner</small>
        </button>
        <button onClick={() => onConnect("issuer", "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")}>
          Issuer wallet 2 <small>Hardhat account 2 · authorized</small>
        </button>
        <button onClick={() => onConnect("verifier", "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc")}>
          Verifier wallet <small>Hardhat account 5 · read-only</small>
        </button>
      </div>
      <small className="login-note">
        {isMobile ? "Open this page inside MetaMask Mobile to connect your wallet" : "No email, password, or role selector · demo addresses are local fixtures"}
      </small>
    </main>
  );
}

function roleForAddress(address: string): Role {
  const normalized = address.toLowerCase();
  if (normalized.includes("71b4") || normalized.includes("holder"))
    return "holder";
  if (normalized.includes("1111")) return "issuer";
  return "verifier";
}

function shortAddress(address: string): string {
  return address.length > 12
    ? `${address.slice(0, 6)}...${address.slice(-4)}`
    : address;
}

function Steps({ active }: { active: number }) {
  return (
    <div className="step-rail">
      {[
        "Source identity",
        "Build certificate",
        "Issuer approval",
        "Mint & review",
      ].map((label, index) => (
        <div
          className={`rail-step ${index < active ? "done" : ""} ${
            index === active ? "current" : ""
          }`}
          key={label}
        >
          <span>{index < active ? "✓" : `0${index + 1}`}</span>
          <label>{label}</label>
        </div>
      ))}
    </div>
  );
}

function Identity({
  registered,
  holder,
  issuerRequested,
  issuerVerified,
  onRequestIssuer,
  onVerifyIssuer,
  onRegister,
}: {
  registered: boolean;
  holder: DemoHolder;
  issuerRequested: boolean;
  issuerVerified: boolean;
  onRequestIssuer: () => void;
  onVerifyIssuer: () => void;
  onRegister: (fingerprint: string, record: DemoHolder) => Promise<boolean>;
}) {
  const [identityRecord, setIdentityRecord] = useState(holder);
  const [documentFingerprint, setDocumentFingerprint] = useState("");
  const [recordReviewed, setRecordReviewed] = useState(false);
  const [registrationError, setRegistrationError] = useState("");
  const [registering, setRegistering] = useState(false);
  useEffect(() => setIdentityRecord(holder), [holder.address]);
  useEffect(() => {
    setDocumentFingerprint("");
    setRecordReviewed(false);
    setRegistrationError("");
  }, [holder.address]);

  return (
    <div className="workspace">
      <div className="identity-ownership">
        <span className="eyebrow">STEP 01 / USER-OWNED</span>
        <h2>Register {identityRecord.did}</h2>
        <p>
          Choose the record that belongs to you. VeriBind hashes the sourced
          data in your browser, then your wallet signs the registration. The
          institution never registers your identity for you.
        </p>
      </div>
      <div className="content-grid">
        <section className="primary-column">
          <SourceCard scanned={Boolean(documentFingerprint)} />
          <IdentityFields holder={identityRecord} />
          <DocumentCapture onExtracted={(record, fingerprint) => { setIdentityRecord({ ...holder, ...record, docHash: `0x${fingerprint}` }); setDocumentFingerprint(fingerprint); setRecordReviewed(false); setRegistrationError(""); }} />
          {documentFingerprint && (
            <IdentityReview
              record={identityRecord}
              onChange={(record) => { setIdentityRecord(record); setRecordReviewed(false); }}
              onConfirm={() => {
                if (!identityRecord.name.trim()) return setRegistrationError("Enter the holder's name before confirming the scanned record.");
                setRegistrationError("");
                setRecordReviewed(true);
              }}
              reviewed={recordReviewed}
            />
          )}
          <div className="selected-did"><span>Selected DID</span><strong>{identityRecord.did}</strong><small>{identityRecord.name} · {identityRecord.credential}</small></div>
          <button
            className="primary-action"
            onClick={async () => {
              setRegistrationError("");
              if (!documentFingerprint) return setRegistrationError("Scan an identity document before registering a real wallet DID.");
              if (!recordReviewed) return setRegistrationError("Review and confirm the extracted identity details first.");
              setRegistering(true);
              try {
                if (!await onRegister(documentFingerprint, identityRecord)) setRegistrationError("This document fingerprint is already registered to another wallet.");
              } catch (reason) {
                setRegistrationError(reason instanceof Error ? reason.message : "Identity registration failed.");
              } finally {
                setRegistering(false);
              }
            }}
            disabled={registered || registering}
          >
            {registered
              ? "Identity registered on DIDRegistry"
              : registering ? "Waiting for wallet confirmation..."
              : !documentFingerprint ? "Scan document to continue" : !recordReviewed ? "Review extracted record" : "Sign & register my identity"}
            <span>→</span>
          </button>
          {registrationError && <p className="presentation-error">{registrationError}</p>}
          <p className="helper">
            Only the hash is written on-chain. Your name and source record stay
            private.
          </p>
          <div className="issuer-access">
            <div>
              <span className="eyebrow">INSTITUTIONAL ACCESS</span>
              <strong>{issuerVerified ? "Issuer accreditation verified" : "Are you an institution?"}</strong>
              <p>
                Issuer access requires evidence that your organization is
                accredited. A DID alone never grants minting permission.
              </p>
            </div>
            {issuerVerified ? (
              <button className="secondary-action" onClick={onVerifyIssuer}>Open issuer workspace <span>→</span></button>
            ) : (
              <button className="secondary-action" onClick={onRequestIssuer}>
                I am an issuer <span>→</span>
              </button>
            )}
          </div>
          {issuerRequested && !issuerVerified && (
            <IssuerVerification onVerified={onVerifyIssuer} />
          )}
        </section>
        <aside className="side-panel">
          <PanelTitle title="What happens" eyebrow="YOUR WALLET" />
          <div className="boundary-list">
            <Boundary label="1. Source" value="Verified record" />
            <Boundary label="2. Hash" value="Browser only" />
            <Boundary label="3. Sign" value="Your wallet" />
            <Boundary label="4. Store" value="Address → docHash" />
          </div>
          <div className="panel-callout">
            <span>i</span>
            <p>
              This demo uses synthetic records. Registration proves which hash
              your wallet approved, not that the upstream source is truthful.
            </p>
          </div>
        </aside>
      </div>
    </div>
  );
}

function IdentityReview({
  record,
  onChange,
  onConfirm,
  reviewed,
}: {
  record: DemoHolder;
  onChange: (record: DemoHolder) => void;
  onConfirm: () => void;
  reviewed: boolean;
}) {
  return (
    <div className="identity-review">
      <div>
        <span className="eyebrow">REVIEW BEFORE SIGNING</span>
        <strong>Check the extracted record</strong>
        <p>OCR can make mistakes. Correct these values before the wallet signs the DID hash.</p>
      </div>
      <label className="field-label">Name<input value={record.name} onChange={(event) => onChange({ ...record, name: event.target.value })} /></label>
      <label className="field-label">Credential<input value={record.credential} onChange={(event) => onChange({ ...record, credential: event.target.value })} /></label>
      <label className="field-label">Institution<input value={record.institution} onChange={(event) => onChange({ ...record, institution: event.target.value })} /></label>
      <button className="secondary-action" onClick={onConfirm}>{reviewed ? "Record reviewed" : "Confirm extracted record"}<span>✓</span></button>
    </div>
  );
}

function IssuerVerification({ onVerified }: { onVerified: () => void }) {
  const [documentType, setDocumentType] = useState("Accreditation certificate");
  const [reference, setReference] = useState("");
  const [organization, setOrganization] = useState("");
  const [error, setError] = useState("");

  const verify = () => {
    if (!organization.trim() || !reference.trim()) {
      setError("Add the institution name and government reference before submitting.");
      return;
    }
    setError("");
    onVerified();
  };

  return (
    <div className="issuer-verification">
      <span className="eyebrow">GOVERNMENT ACCREDITATION CHECK</span>
      <h3>Verify the institution before issuing</h3>
      <p>
        In production this record would be checked against a government or
        approved accreditation registry. This demo records the evidence flow;
        it does not contact a real government service.
      </p>
      <label className="field-label">
        Institution name
        <input value={organization} onChange={(event) => setOrganization(event.target.value)} placeholder="Northstar Institute of Technology" />
      </label>
      <label className="field-label">
        Evidence type
        <select value={documentType} onChange={(event) => setDocumentType(event.target.value)}>
          <option>Accreditation certificate</option>
          <option>Government registration certificate</option>
          <option>Education authority license</option>
        </select>
      </label>
      <label className="field-label">
        Government reference or registry ID
        <input value={reference} onChange={(event) => setReference(event.target.value)} placeholder="ACC-2026-0001" />
      </label>
      <button className="primary-action" onClick={verify}>Submit accreditation evidence <span>→</span></button>
      {error && <p className="presentation-error">{error}</p>}
    </div>
  );
}

function DocumentCapture({ onExtracted }: { onExtracted: (record: Partial<DemoHolder>, fingerprint: string) => void }) {
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");

  const scan = async (file: File) => {
    setError("");
    setStatus("");
    if (!file.type.startsWith("image/")) return setError("Choose an image file such as JPG, PNG, or WebP.");
    if (file.size > 20 * 1024 * 1024) return setError("Choose an image smaller than 20 MB.");
    setStatus("Reading document locally...");
    try {
      const bitmap = await createImageBitmap(file);
      const scale = Math.min(1.5, 2600 / Math.max(bitmap.width, bitmap.height));
      const canvas = document.createElement("canvas");
      canvas.width = Math.max(1, Math.round(bitmap.width * scale));
      canvas.height = Math.max(1, Math.round(bitmap.height * scale));
      const context = canvas.getContext("2d");
      if (!context) throw new Error("Could not prepare the image for local scanning.");
      context.filter = "grayscale(1) contrast(1.2)";
      context.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
      bitmap.close();
      const { default: Tesseract } = await import("tesseract.js");
      const result = await Tesseract.recognize(canvas, "eng", {
        logger: (message) => {
          if (message.status === "recognizing text") setStatus(`Scanning document ${Math.round((message.progress ?? 0) * 100)}%`);
        },
      });
      const text = result.data.text.trim();
      const fingerprint = await fingerprintDocumentText(text);
      const extractedName = extractDocumentName(text);
      onExtracted({ name: extractedName ?? "", credential: "Document record scanned", institution: "Document source pending" }, fingerprint);
      setStatus("Document scanned locally. Review the extracted record before signing.");
    } catch (reason) {
      setStatus("");
      setError(reason instanceof Error ? reason.message : "Document OCR failed.");
    }
  };

  return (
    <div className="document-capture">
      <div>
        <span className="eyebrow">REQUIRED / LOCAL OCR</span>
        <strong>Scan your identity document</strong>
        <p>Image text is processed in this browser. Do not upload Aadhaar or other sensitive documents to an untrusted server.</p>
      </div>
      <label className="upload-button">Choose document image<input type="file" accept="image/*" onChange={(event) => { const file = event.target.files?.[0]; if (file) void scan(file); event.currentTarget.value = ""; }} /></label>
      {status && <small>{status}</small>}
      {error && <p className="presentation-error">{error}</p>}
    </div>
  );
}

function SourceCard({ scanned }: { scanned: boolean }) {
  return (
    <div className="source-card">
      <div className="source-logo">{scanned ? "OCR" : "DL"}</div>
      <div className="source-copy">
        <strong>{scanned ? "Local document scan" : "DigiLocker fixture"}</strong>
        <span>{scanned ? "Browser OCR adapter · review required" : "Verified source adapter · fixture-v1"}</span>
        <small>{scanned ? "No document uploaded" : "Record DL-DEMO-2048-118 · checked 20 Sep 2026"}</small>
      </div>
      <span className="verified-badge">{scanned ? "local extraction" : "✓ verified source"}</span>
    </div>
  );
}

function IdentityFields({ holder }: { holder: DemoHolder }) {
  return (
    <div className="identity-preview">
      {[["Name", holder.name], ["Credential", holder.credential]].map(([label, value]) => (
        <div className="data-row" key={label}>
          <span>{label}</span>
          <strong>{value}</strong>
        </div>
      ))}
      <div className="hash-row">
        <span>Local docHash</span>
        <code>{holder.docHash || "Not generated"}</code>
        <span className="local-badge">never uploaded</span>
      </div>
    </div>
  );
}

function Institution({
  chainBacked,
  chainCredential,
  chainIssuance,
  issuanceBusy,
  onIssuerAction,
  status,
  minted,
  setMinted,
  onCheckDid,
  onCheckDuplicate,
  onPrepare,
  transactionHash,
}: {
  chainBacked: boolean;
  chainCredential: { tokenId: string; merkleRoot: string; issuanceDigest: string; issuedAt: number; expiresAt: number } | null;
  chainIssuance: { id: string; approvals: number; threshold: number; finalized: boolean; approvedByMe: boolean; merkleRoot: string; expiresAt: number } | null;
  issuanceBusy: boolean;
  onIssuerAction: (action: "propose" | "approve" | "finalize") => Promise<void>;
  status: Status;
  minted: boolean;
  setMinted: (value: boolean) => void;
  onCheckDid: (address: string, demoMode?: boolean) => Promise<{ registered: boolean; source: "on-chain" | "demo-local" }>;
  onCheckDuplicate: (address: string, program: string) => Promise<{ duplicate: boolean; source: "on-chain" | "demo-local"; tokenId?: string }>;
  onPrepare: (packageData: CredentialPackage, address: string) => void;
  transactionHash: string;
}) {
  const [studentAddress, setStudentAddress] = useState("");
  const [didResult, setDidResult] = useState<{ registered: boolean; source: "on-chain" | "demo-local" } | null>(null);
  const [didError, setDidError] = useState("");
  const [dataSource, setDataSource] = useState<"institution" | "upload">("institution");
  const [demoEnabled, setDemoEnabled] = useState(false);
  const [record, setRecord] = useState<Partial<CertificateRecord>>({});
  const [uploadName, setUploadName] = useState("");
  const [dataError, setDataError] = useState("");
  const [duplicate, setDuplicate] = useState<{ tokenId?: string; source: "on-chain" | "demo-local" } | null>(null);
  const [packageData, setPackageData] = useState<CredentialPackage | null>(null);
  const [building, setBuilding] = useState(false);
  const [buildError, setBuildError] = useState("");

  const didPassed = didResult?.registered === true;
  const dataPassed = Boolean(packageData);
  const effectiveRecord = {
    wallet_address: studentAddress,
    ...(demoEnabled ? {
    wallet_address: studentAddress,
    program: "Bachelor of Computer Science",
    name: "Ananya Rao",
    credential: "Bachelor of Computer Science",
    institution: "Northstar Institute of Technology",
    issued: "14 September 2026",
    } : record),
  };
  const dataReady = (() => {
    try {
      return canBuildCredential(effectiveRecord as Record<string, unknown>, studentAddress, didPassed);
    } catch {
      return false;
    }
  })();

  const checkDid = async () => {
    setDidError("");
    setDidResult(null);
    setPackageData(null);
    if (!isRealWalletAddress(studentAddress)) {
      setDidError("Enter a valid Ethereum wallet address.");
      return;
    }
    try {
      const result = await onCheckDid(studentAddress, demoEnabled);
      setDidResult(result);
      if (!result.registered) setDidError("No DID found");
    } catch (reason) {
      setDidError(reason instanceof Error ? reason.message : "Unable to check DID.");
    }
  };

  const loadUpload = async (file: File) => {
    setDataError("");
    setPackageData(null);
    setUploadName(file.name);
    try {
      const parsed = parseCertificateUpload(await file.text(), file.name, studentAddress);
      setRecord(parsed);
    } catch (reason) {
      setDataError(reason instanceof Error ? reason.message : "Unable to validate upload.");
    }
  };

  const build = async () => {
    setBuildError("");
    setDuplicate(null);
    if (!didPassed) return setBuildError("Check DID and confirm Registered DID before building.");
    if (!isRealWalletAddress(studentAddress)) return setBuildError("Enter a valid Ethereum wallet address.");
    try {
      const validRecord = validateCertificateRecord(effectiveRecord as Record<string, unknown>, studentAddress);
      const duplicateResult = await onCheckDuplicate(studentAddress, validRecord.program);
      if (duplicateResult.duplicate) {
        setDuplicate({ tokenId: duplicateResult.tokenId, source: duplicateResult.source });
        setBuildError(`A credential already exists for this address and program${duplicateResult.tokenId ? ` (token #${duplicateResult.tokenId})` : ""}. Issuance is blocked.`);
        return;
      }
      setBuilding(true);
      const built = await buildCredentialPackage(validRecord, {
        apiUrl: import.meta.env.VITE_PINATA_API_URL,
        jwt: import.meta.env.VITE_PINATA_JWT,
      });
      setPackageData(built);
      onPrepare(built, studentAddress);
    } catch (reason) {
      setBuildError(reason instanceof Error ? reason.message : "Credential package build failed.");
    } finally {
      setBuilding(false);
    }
  };

  const updateRecord = (field: keyof CertificateRecord, value: string) => {
    setRecord((current) => ({ ...current, [field]: value }));
    setPackageData(null);
    setDataError("");
  };

  return (
    <div className="workspace">
      <Steps active={chainCredential ? 3 : chainIssuance ? 2 : packageData ? 1 : didPassed ? 0 : 0} />
      <div className="content-grid">
        <section className="primary-column">
          <div className="section-heading">
            <div><span className="eyebrow">PHASE 02 / CERTIFICATE PREPARATION</span><h2>Prepare the credential</h2></div>
            <span className="state-tag">{chainBacked ? "ON-CHAIN" : "DEMO-LOCAL"}</span>
          </div>
          <div className="issuance-card">
            <div className="section-heading"><div><span className="eyebrow">STEP 01</span><h3>Check student identity</h3></div><ProvenanceBadge label={didResult?.source ?? (chainBacked ? "on-chain" : "demo-local")} /></div>
            <div className="address-row">
              <input value={studentAddress} onChange={(event) => { setStudentAddress(event.target.value); setDidResult(null); setPackageData(null); }} placeholder="0x student wallet address" />
              <button className="secondary-action" onClick={() => void checkDid()}>Check DID</button>
            </div>
            {didResult && <p className={didResult.registered ? "success-copy" : "presentation-error"}>{didResult.registered ? "Registered DID" : "No DID found"}{didResult.source === "demo-local" ? " · demo-local" : ""}</p>}
            {didError && <p className="presentation-error">{didError}</p>}
          </div>
          <div className="issuance-card">
            <div className="section-heading"><div><span className="eyebrow">STEP 02</span><h3>Load certificate data</h3></div><ProvenanceBadge label={packageData ? "demo-local" : "not loaded"} /></div>
            <div className="source-toggle">
              <label><input type="radio" checked={dataSource === "institution"} onChange={() => { setDataSource("institution"); setPackageData(null); }} /> Use institution record</label>
              <label><input type="radio" checked={dataSource === "upload"} onChange={() => { setDataSource("upload"); setPackageData(null); }} /> Upload personal data</label>
            </div>
            <label className="field-label"><input type="checkbox" checked={demoEnabled} onChange={(event) => { setDemoEnabled(event.target.checked); setPackageData(null); }} /> Enable demo-local sample data</label>
            {dataSource === "upload" && !demoEnabled ? (
              <label className="field-label">JSON or CSV file<input type="file" accept=".json,.csv,application/json,text/csv" onChange={(event) => { const file = event.target.files?.[0]; if (file) void loadUpload(file); }} /></label>
            ) : (
              <div className="data-form">
                {(["program", "name", "credential", "institution", "issued"] as const).map((field) => <label className="field-label" key={field}>{field}<input value={String(effectiveRecord[field] ?? "")} onChange={(event) => updateRecord(field, event.target.value)} disabled={demoEnabled} /></label>)}
                <label className="field-label">Optional photo commitment<input value={String(effectiveRecord.photo ?? "")} onChange={(event) => updateRecord("photo", event.target.value)} disabled={demoEnabled} /></label>
              </div>
            )}
            {uploadName && <small>Loaded: {uploadName}</small>}
            {dataReady && <div className="request-details"><div><span>Preview</span><strong>{String(effectiveRecord.name)} · {String(effectiveRecord.program)}</strong></div><div><span>Wallet</span><strong>{String(effectiveRecord.wallet_address)}</strong></div><div><span>Institution</span><strong>{String(effectiveRecord.institution)}</strong></div></div>}
            {dataError && <p className="presentation-error">{dataError}</p>}
            <p className="helper">Required fields: wallet_address, program, name, credential, institution, issued. Personal fields stay off-chain.</p>
          </div>
          <div className="issuance-card">
            <div className="section-heading"><div><span className="eyebrow">STEP 03</span><h3>Build credential</h3></div><ProvenanceBadge label={packageData ? "demo-local" : "waiting"} /></div>
            {packageData && <div className="package-line"><div><strong>Credential package ready</strong><span>{packageData.fields.length} fields · AES-GCM encrypted</span></div><code>{packageData.cidIsPlaceholder ? "CID placeholder" : packageData.cid}</code></div>}
            {duplicate && <p className="presentation-error">Duplicate blocked{duplicate.tokenId ? ` · existing token #${duplicate.tokenId}` : ""} · {duplicate.source}</p>}
            {buildError && <p className="presentation-error">{buildError}</p>}
            <button className="primary-action" onClick={() => void build()} disabled={!didPassed || !dataReady || building || Boolean(packageData)}>{building ? "Building package..." : packageData ? "Credential package built" : "Build credential"}<span>→</span></button>
          </div>
        </section>
        <aside className="side-panel">
          <PanelTitle title="Issuer approval" eyebrow={chainBacked ? `${chainIssuance?.threshold ?? 2} ISSUERS REQUIRED` : "DEMO-LOCAL"} />
          <div className="approval-bar">
            <span style={{ width: `${chainIssuance ? Math.min(100, chainIssuance.approvals / chainIssuance.threshold * 100) : 0}%` }} />
          </div>
          {chainBacked ? (
            <div className="request-details">
              <div><span>On-chain approval quorum</span><strong>{chainIssuance ? `${chainIssuance.approvals} / ${chainIssuance.threshold}` : "2 required"}</strong></div>
              <div><span>Issuance ID</span><strong>{chainIssuance?.id ?? "Not proposed"}</strong></div>
              <div><span>Expiry</span><strong>{chainIssuance?.expiresAt ? new Date(chainIssuance.expiresAt * 1000).toLocaleDateString() : "No expiry"}</strong></div>
            </div>
          ) : (
            <p className="helper">Demo-local approval state is disabled for production issuance. Configure the contract to collect real issuer approvals.</p>
          )}
          {chainBacked ? (
            chainCredential ? <p className="state-tag">NFT #{chainCredential.tokenId} exists on-chain · {status}</p> : !chainIssuance ? (
              <button className="primary-action" onClick={() => void onIssuerAction("propose").catch(() => undefined)} disabled={!packageData || issuanceBusy}>
                {issuanceBusy ? "Waiting for MetaMask..." : "Propose issuance on-chain"}<span>→</span>
              </button>
            ) : !chainIssuance.approvedByMe ? (
              <button className="primary-action" onClick={() => void onIssuerAction("approve").catch(() => undefined)} disabled={issuanceBusy}>
                {issuanceBusy ? "Waiting for MetaMask..." : `Approve issuance #${chainIssuance.id}`}<span>→</span>
              </button>
            ) : chainIssuance.approvals >= chainIssuance.threshold ? (
              <button className="primary-action" onClick={() => void onIssuerAction("finalize").catch(() => undefined)} disabled={issuanceBusy}>
                {issuanceBusy ? "Waiting for MetaMask..." : "Finalize & mint NFT"}<span>→</span>
              </button>
            ) : <p className="identity-gate"><strong>Waiting for second issuer</strong><span>Switch MetaMask to the other authorized issuer account to approve.</span></p>
          ) : (
            <p className="helper">No on-chain transaction is available in demo-local mode.</p>
          )}
          {transactionHash && <p className="success-copy">on-chain · tx {shortAddress(transactionHash)}</p>}
          {packageData?.cidIsPlaceholder && <p className="helper">IPFS CID is a clearly marked placeholder because Pinata is not configured.</p>}
          <p className="helper">
            {chainBacked
              ? "Issuance proposals, issuer approvals, and final minting are on-chain MetaMask transactions. A separate holder transaction confirms the credential."
              : "Issuer data is demo-local until an official contract is configured. Issuers are trusted to supply accurate data."}
          </p>
        </aside>
      </div>
    </div>
  );
}

function ProvenanceBadge({ label }: { label: string }) {
  return <span className="verified-badge">{label}</span>;
}

function Holder({
  minted,
  holder,
  chainCredential,
  consentRequest,
  consentError,
  onConsentDecision,
  status,
  setStatus,
  field,
  proofRequested,
  proofSent,
  proofDenied,
  setProofSent,
  setProofDenied,
}: {
  minted: boolean;
  holder: DemoHolder;
  chainCredential: { tokenId: string; merkleRoot: string; issuanceDigest: string; issuedAt: number; expiresAt: number } | null;
  consentRequest: ConsentRequest | null;
  consentError: string;
  onConsentDecision: (decision: "approve" | "reject") => Promise<void>;
  status: Status;
  setStatus: (value: Status) => void;
  field: string;
  proofRequested: boolean;
  proofSent: boolean;
  proofDenied: boolean;
  setProofSent: (value: boolean) => void;
  setProofDenied: (value: boolean) => void;
}) {
  if (!minted)
    return (
      <Empty
        title="Nothing to review yet"
        text="The institution must register the identity, collect 3 issuer approvals, and mint the Pending credential first."
      />
    );
  if (consentRequest && consentRequest.status === "Pending")
    return (
      <ConsentInbox
        request={consentRequest}
        error={consentError}
        onDecision={onConsentDecision}
      />
    );
  if (proofRequested && status === "Confirmed" && !proofSent && !proofDenied)
    return (
      <div className="proof-inbox">
        <span className="eyebrow">NEW REQUEST / FROM VERIFIER</span>
        <h2>Someone is asking for one field</h2>
        <p>
          Share only the selected claim and its Merkle proof. Your document and
          encryption key stay private.
        </p>
        <div className="request-preview">
          <span>Requested field</span>
          <strong>{field}</strong>
          <small>Credential #001 · proof will be generated locally</small>
        </div>
        <div className="proof-decision"><button className="confirm-button" onClick={() => setProofSent(true)}>Share this proof <span>→</span></button><button className="dispute-button" onClick={() => setProofDenied(true)}>Deny request</button></div>
      </div>
    );
  if (status === "Confirmed")
    return <VerifiedCredential holder={holder} chainCredential={chainCredential} field={field} proofRequested={proofRequested} proofSent={proofSent} proofDenied={proofDenied} />;
  return (
    <div className="workspace">
      <div className="status-banner">
        <div>
          <span className="eyebrow">CREDENTIAL #{chainCredential?.tokenId ?? "001"} / RECIPIENT VIEW</span>
          <h2>Review before you confirm</h2>
          <p>
            The institution issued a credential bound to your registered
            identity. Read the decrypted copy privately, then choose a permanent
            outcome.
          </p>
        </div>
        <StatusPill status={status} />
      </div>
      <div className="content-grid holder-grid">
        <section className="primary-column">
          <div className="certificate-sheet">
            <div className="sheet-top">
              <span className="document-kicker">NORTHSTAR INSTITUTE</span>
              <span className="sheet-stamp">DECRYPTED LOCALLY</span>
            </div>
            <h2>Certificate of completion</h2>
            <p className="recipient-name">{holder.name}</p>
            <div className="certificate-rule" />
            {[["Credential", holder.credential], ["Institution", holder.institution], ["Issued", "14 September 2026"]].map(([label, value]) => (
              <div className="cert-row" key={label}>
                <span>{label}</span>
                <strong>{value}</strong>
              </div>
            ))}
            <div className="sheet-footer">
              <span>Schema v1 · issued 14 Sep 2026</span>
              <span>Root {chainCredential?.merkleRoot ?? "0x6a1f...d440 (demo)"}</span>
            </div>
          </div>
          {status === "Pending" && (
            <div className="decision-row">
              <button
                className="confirm-button"
                onClick={() => setStatus("Confirmed")}
              >
                Confirm credential <span>✓</span>
              </button>
              <button
                className="dispute-button"
                onClick={() => setStatus("Disputed")}
              >
                Dispute this credential
              </button>
            </div>
          )}
          {status === "Disputed" && (
            <div className="dispute-notice">
              <strong>Dispute recorded permanently.</strong>
              <span>The institution must issue a new credential.</span>
            </div>
          )}
        </section>
        <aside className="side-panel">
          <PanelTitle title="On-chain receipt" eyebrow="PUBLIC INTEGRITY" />
          <Boundary label="Lifecycle" value={status} />
          <Boundary label="Recipient binding" value={shortAddress(holder.address)} />
          <Boundary label="Issuer quorum" value="3 of 5" />
          <Boundary label="Soulbound" value="Yes" />
        </aside>
      </div>
    </div>
  );
}

function ConsentInbox({ request, error, onDecision }: { request: ConsentRequest; error: string; onDecision: (decision: "approve" | "reject") => Promise<void> }) {
  return (
    <div className="workspace">
      <div className="consent-notification">
        <span className="eyebrow">NEW VERIFICATION REQUEST</span>
        <h2>{request.organizationName} wants to verify your credential</h2>
        <p>Review the requested fields and purpose before sharing anything.</p>
      </div>
      <section className="consent-card">
        <div className="consent-card-heading"><div><span className="eyebrow">ORGANIZATION CONSENT</span><h3>{request.organizationName}</h3></div><span className="status-pill pending">Pending</span></div>
        <div className="consent-details">
          <Boundary label="Credential" value={request.requestedCredential} />
          <Boundary label="Purpose" value={request.purpose} />
          <Boundary label="Expires" value={new Date(request.expiresAt * 1000).toLocaleDateString()} />
        </div>
        <strong className="consent-fields-title">Requested data</strong>
        <div className="consent-fields">{request.requestedFields.map((requestedField) => <span key={requestedField}>{requestedField}</span>)}</div>
        <p className="consent-note">Approve to create Merkle proofs for only these fields and sign the consent with your wallet.</p>
        <div className="proof-decision"><button className="confirm-button" onClick={() => void onDecision("approve")}>Approve & sign <span>→</span></button><button className="dispute-button" onClick={() => void onDecision("reject")}>Reject</button></div>
        {error && <p className="presentation-error">{error}</p>}
      </section>
    </div>
  );
}

function VerifiedCredential({ holder, chainCredential, field, proofRequested, proofSent, proofDenied }: { holder: DemoHolder; chainCredential: { tokenId: string; merkleRoot: string } | null; field: string; proofRequested: boolean; proofSent: boolean; proofDenied: boolean }) {
  return <div className="workspace"><div className="verified-list-header"><div><span className="eyebrow">YOUR VERIFIED CREDENTIALS</span><h2>Credential #{chainCredential?.tokenId ?? "001"}</h2><p>Confirmed by you · full document remains private</p></div><StatusPill status="Confirmed" /></div><div className="verified-list"><div className="verified-list-item"><span className="verified-check">✓</span><div><strong>{holder.credential}</strong><small>{holder.institution} · issued 14 September 2026</small></div><code>root {chainCredential?.merkleRoot ?? "0x6a1f...d440 (demo)"}</code></div></div>{proofRequested && <div className={`request-status ${proofDenied ? "denied" : proofSent ? "shared" : "waiting"}`}><strong>{proofDenied ? "You denied the verifier request" : proofSent ? `You shared only the ${field} proof` : `Verifier requested: ${field}`}</strong><span>{proofDenied ? "No document or field value was shared." : proofSent ? "The field value and sibling hashes were sent. Your document stayed private." : "Open this request to share or deny it."}</span></div>}</div>;
}

const presentationChainId = Number(import.meta.env.VITE_OFFICIAL_CHAIN_ID || 11155111);
const presentationContract = import.meta.env.VITE_VERIBIND_CONTRACT_ADDRESS || "0x0000000000000000000000000000000000000000";
const credentialReadAbi = [
  "function credentialRecipient(uint256) view returns (address)",
  "function holderCredentialCount(address holder) view returns (uint256)",
  "function holderCredentialAt(address holder, uint256 index) view returns (uint256)",
  "function credentialStatus(uint256) view returns (uint8)",
  "function credentialMerkleRoot(uint256) view returns (bytes32)",
  "function credentialPhotoHash(uint256) view returns (bytes32)",
  "function credentialIssuanceDigest(uint256) view returns (bytes32)",
  "function credentialIssuedAt(uint256) view returns (uint64)",
  "function credentialExpiresAt(uint256) view returns (uint64)",
];

async function makePresentation(provider: BrowserProvider, recipientAddress: string, holder: DemoHolder, field: string, chainCredential: { tokenId: string; merkleRoot: string; issuanceDigest: string; issuedAt: number; expiresAt: number } | null, challenge?: VerificationChallenge): Promise<VeribindPresentation> {
  const allFields = credentialFields(holder);
  const leaves = await Promise.all(allFields.map(([name, value]) => hashField(1, name.toLowerCase(), value)));
  const fieldIndex = allFields.findIndex(([name]) => name.toLowerCase() === field.toLowerCase());
  if (fieldIndex < 0) throw new Error(`Unsupported presentation field: ${field}`);
  const calculatedMerkleRoot = await buildMerkleRoot(leaves);
  if (chainCredential && calculatedMerkleRoot.toLowerCase() !== chainCredential.merkleRoot.toLowerCase()) {
    throw new Error("The local holder profile does not match the credential data committed on-chain.");
  }
  const certificateMerkleRoot = chainCredential?.merkleRoot ?? calculatedMerkleRoot;
  const merkleProof = await buildMerkleProof(leaves, fieldIndex);
  const signed = await signPresentation(provider, {
    type: "veribind-presentation",
    version: 1,
    chainId: presentationChainId,
    contractAddress: presentationContract,
    tokenId: chainCredential?.tokenId ?? "1",
    recipientAddress,
    credentialStatus: "Confirmed",
    disclosures: [{ fieldName: field.toLowerCase(), fieldValue: allFields[fieldIndex][1], fieldHash: leaves[fieldIndex], fieldIndex, merkleProof }],
    certificateMerkleRoot,
    issuanceDigest: chainCredential?.issuanceDigest ?? "0x0000000000000000000000000000000000000000000000000000000000000000",
    issuedAt: chainCredential?.issuedAt ?? 1790035200,
    expiresAt: chainCredential?.expiresAt ?? 0,
    nonce: randomNonce(),
    verificationChallenge: challenge,
  });
  return challenge ? { ...signed, challengeSignature: await signVerificationChallenge(provider, challenge) } : signed;
}

function credentialFields(holder: DemoHolder): [string, string][] {
  return [
    ["name", holder.name],
    ["program", holder.program ?? holder.credential],
    ["credential", holder.credential],
    ["institution", holder.institution],
    ["issued", holder.issued ?? "14 September 2026"],
    ...(holder.photoHash ? [["photo hash", holder.photoHash] as [string, string]] : []),
  ];
}

async function signConsentResponse(provider: BrowserProvider, request: ConsentRequest | null, holder: DemoHolder, recipientAddress: string): Promise<ConsentResponse> {
  if (!request) throw new Error("No active organization request.");
  const allFields = credentialFields(holder);
  const leaves = await Promise.all(allFields.map(([name, value]) => hashField(1, name.toLowerCase(), value)));
  const disclosures = await Promise.all(request.requestedFields.map(async (requestedField) => {
    const fieldIndex = allFields.findIndex(([name]) => name.toLowerCase() === requestedField.toLowerCase());
    if (fieldIndex < 0) throw new Error(`Unsupported requested field: ${requestedField}`);
    return { fieldName: requestedField.toLowerCase(), fieldValue: allFields[fieldIndex][1], fieldHash: leaves[fieldIndex], fieldIndex, merkleProof: await buildMerkleProof(leaves, fieldIndex) };
  }));
  const certificateMerkleRoot = await buildMerkleRoot(leaves);
  const unsigned = {
    type: "veribind-verification-response" as const,
    version: 1 as const,
    requestId: request.requestId,
    organizationId: request.organizationId,
    chainId: presentationChainId,
    contractAddress: presentationContract,
    tokenId: "1",
    recipientAddress,
    disclosures,
    certificateMerkleRoot,
    consentGranted: true as const,
    expiresAt: request.expiresAt,
  };
  const digest = keccak256(toUtf8Bytes(`veribind-consent-v1|${JSON.stringify(unsigned)}`));
  const recipientSignature = await (await provider.getSigner()).signMessage(getBytes(digest));
  return { ...request, ...unsigned, status: "Approved", recipientSignature, nonce: request.nonce, organizationName: request.organizationName, requestedCredential: request.requestedCredential, requestedFields: request.requestedFields, purpose: request.purpose };
}

async function checkConsentResponse(response: ConsentResponse, request: ConsentRequest): Promise<{ valid: boolean; reason?: string }> {
  if (response.requestId !== request.requestId || response.organizationId !== request.organizationId) return { valid: false, reason: "Request binding mismatch" };
  if (response.expiresAt < Math.floor(Date.now() / 1000)) return { valid: false, reason: "Consent response expired" };
  const unsigned = {
    type: response.type,
    version: response.version,
    requestId: response.requestId,
    organizationId: response.organizationId,
    chainId: response.chainId,
    contractAddress: response.contractAddress,
    tokenId: response.tokenId,
    recipientAddress: response.recipientAddress,
    disclosures: response.disclosures,
    certificateMerkleRoot: response.certificateMerkleRoot,
    consentGranted: response.consentGranted,
    expiresAt: response.expiresAt,
  };
  const recovered = verifyMessage(getBytes(keccak256(toUtf8Bytes(`veribind-consent-v1|${JSON.stringify(unsigned)}`))), response.recipientSignature);
  if (recovered.toLowerCase() !== response.recipientAddress.toLowerCase()) return { valid: false, reason: "Invalid recipient signature" };
  for (const disclosure of response.disclosures) {
    const leaf = await hashField(1, disclosure.fieldName, disclosure.fieldValue);
    if (!await verifyMerkleProof(leaf, disclosure.merkleProof, response.certificateMerkleRoot)) return { valid: false, reason: `Merkle proof failed for ${disclosure.fieldName}` };
  }
  return { valid: true };
}

function QrCameraScanner({ onScan, onError, onClose }: { onScan: (value: string) => void; onError: (message: string) => void; onClose: () => void }) {
  const videoRef = useRef<HTMLVideoElement>(null);
  useEffect(() => {
    let stream: MediaStream | undefined;
    let timer: number | undefined;
    let stopped = false;
    const canvas = document.createElement("canvas");
    const start = async () => {
      if (!navigator.mediaDevices?.getUserMedia) {
        onError("Camera access is unavailable. Open VeriBind through HTTPS or localhost.");
        return;
      }
      try {
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: "environment" } }, audio: false });
        if (!videoRef.current) return;
        videoRef.current.srcObject = stream;
        await videoRef.current.play();
        timer = window.setInterval(() => {
          const video = videoRef.current;
          if (stopped || !video || video.readyState < 2 || !video.videoWidth) return;
          canvas.width = video.videoWidth;
          canvas.height = video.videoHeight;
          const context = canvas.getContext("2d");
          if (!context) return;
          context.drawImage(video, 0, 0, canvas.width, canvas.height);
          const pixels = context.getImageData(0, 0, canvas.width, canvas.height);
          const decoded = jsQR(pixels.data, pixels.width, pixels.height);
          if (decoded) {
            stopped = true;
            onScan(decoded.data);
          }
        }, 250);
      } catch (reason) {
        onError(reason instanceof Error ? reason.message : "Camera permission was denied.");
      }
    };
    void start();
    return () => {
      stopped = true;
      if (timer) window.clearInterval(timer);
      stream?.getTracks().forEach((track) => track.stop());
    };
  }, [onError, onScan]);
  return <div className="qr-camera-scanner"><video ref={videoRef} playsInline muted /><p>Point the camera at the verifier challenge QR.</p><button type="button" className="secondary-action" onClick={onClose}>Close scanner</button></div>;
}

function Presentation({ minted, status, holder, chainCredential, recipientAddress, field, consentRequest, consentResponse, onCreateConsentRequest, onWalletConnected }: { minted: boolean; status: Status; holder: DemoHolder; chainCredential: { tokenId: string; merkleRoot: string; issuanceDigest: string; issuedAt: number; expiresAt: number } | null; recipientAddress: string; field: string; consentRequest: ConsentRequest | null; consentResponse: ConsentResponse | null; onCreateConsentRequest: (request: ConsentRequest) => void; onWalletConnected: (address: string) => void }) {
  const [mode, setMode] = useState<"organization" | "qr">("organization");
  const [selectedField, setSelectedField] = useState(field);
  const [qrData, setQrData] = useState("");
  const [presentation, setPresentation] = useState<VeribindPresentation | null>(null);
  const [error, setError] = useState("");
  const [walletAddress, setWalletAddress] = useState("");
  const [challengeInput, setChallengeInput] = useState("");
  const [challengeScannerOpen, setChallengeScannerOpen] = useState(false);
  const connectHolderWallet = async () => {
    setError("");
    if (!window.ethereum) return setError("MetaMask was not detected. Install the extension to sign this QR.");
    try {
      const accounts = (await window.ethereum.request({ method: "eth_requestAccounts" })) as string[];
      if (!accounts[0]) return setError("No wallet account was selected.");
      setWalletAddress(accounts[0]);
      onWalletConnected(accounts[0]);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Wallet connection was cancelled.");
    }
  };
  const generate = async () => {
    setError("");
    if (!minted || status !== "Confirmed") return setError("Confirm the credential before creating a presentation.");
    if (!window.ethereum) return setError("MetaMask is required because the QR must be signed by the holder wallet.");
    try {
      const provider = new BrowserProvider(window.ethereum as never);
      const accounts = (await provider.send("eth_accounts", [])) as string[];
      if (!accounts[0]) return setError("Connect the holder wallet before generating the signed QR.");
      if (accounts[0].toLowerCase() !== recipientAddress.toLowerCase()) return setError("The connected wallet does not match this credential. Connect the holder wallet.");
      let challenge: VerificationChallenge | undefined;
      if (challengeInput.trim()) {
        try {
          challenge = JSON.parse(challengeInput) as VerificationChallenge;
        } catch {
          return setError("Paste the verifier challenge JSON exactly as provided.");
        }
        if (challenge.recipientAddress.toLowerCase() !== accounts[0].toLowerCase()) return setError("This challenge belongs to a different wallet.");
      }
      const signed = await makePresentation(provider, accounts[0], holder, selectedField, chainCredential, challenge);
      setWalletAddress(accounts[0]);
      setPresentation(signed);
      setQrData(await QRCode.toDataURL(JSON.stringify(signed), { width: 280, margin: 2, errorCorrectionLevel: "M" }));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Wallet signature was cancelled.");
    }
  };
  const handleChallengeScan = (value: string) => {
    try {
      const challenge = JSON.parse(value) as VerificationChallenge;
      if (!challenge.challenge || !challenge.recipientAddress || !challenge.tokenId) throw new Error("This is not a VeriBind verification challenge.");
      setChallengeInput(JSON.stringify(challenge));
      setChallengeScannerOpen(false);
      setPresentation(null);
      setQrData("");
      setError("Challenge scanned. Connect the matching holder wallet and sign the response QR.");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The challenge QR could not be read.");
    }
  };
  return (
    <div className="workspace">
      <div className="presentation-intro">
        <span className="eyebrow">RECIPIENT VERIFICATION OPTIONS</span>
        <h2>Choose how to share</h2>
        <p>Share requested details with an organization or create a holder-signed QR for direct verification.</p>
      </div>
      <div className="presentation-tabs" role="tablist" aria-label="Presentation method">
        <button type="button" role="tab" aria-selected={mode === "organization"} className={mode === "organization" ? "active" : ""} onClick={() => setMode("organization")}>Organization</button>
        <button type="button" role="tab" aria-selected={mode === "qr"} className={mode === "qr" ? "active" : ""} onClick={() => setMode("qr")}>QR presentation</button>
      </div>
      <div className={`presentation-grid ${mode === "organization" ? "organization-mode" : "qr-mode"}`}>
        {mode === "organization" ? (
          <OrganizationShareCard minted={minted} holder={holder} request={consentRequest} response={consentResponse} onCreate={onCreateConsentRequest} />
        ) : (
          <>
            <section className="request-card presentation-quick-card">
              <div className="mode-heading">
                <span className="eyebrow">QUICK QR</span>
                <h3>Create a signed presentation</h3>
                <p>Choose one credential field. Your wallet signs the QR so a verifier can check it directly.</p>
              </div>
              <label className="field-label">
                Field to show
                <select value={selectedField} onChange={(event) => { setSelectedField(event.target.value); setPresentation(null); setQrData(""); }}>
                  <option>Name</option>
                  <option>Credential</option>
                  <option>Institution</option>
                  <option>Issued</option>
                  <option>Photo hash</option>
                </select>
              </label>
              <label className="field-label">
                Fresh verifier challenge (optional)
                <textarea value={challengeInput} onChange={(event) => { setChallengeInput(event.target.value); setPresentation(null); setQrData(""); }} placeholder="Scan the verifier challenge QR or paste its JSON" />
              </label>
              <button type="button" className="secondary-action" onClick={() => setChallengeScannerOpen(true)}>Scan verifier challenge QR</button>
              {challengeScannerOpen && <QrCameraScanner onScan={handleChallengeScan} onError={setError} onClose={() => setChallengeScannerOpen(false)} />}
              <div className="presentation-facts">
                <Boundary label="Status" value={status} />
                <Boundary label="Wallet" value={walletAddress || recipientAddress} />
                <Boundary label="Network" value={`Chain ${presentationChainId}`} />
              </div>
              <div className={`wallet-status ${walletAddress ? "connected" : "disconnected"}`}>
                <span className="green-dot" />
                {walletAddress ? `Holder wallet connected: ${shortAddress(walletAddress)}` : "Holder wallet not connected"}
              </div>
              {!walletAddress && <button className="secondary-action" onClick={() => void connectHolderWallet()}>Connect MetaMask to sign</button>}
              <button className="primary-action" onClick={generate} disabled={!minted || status !== "Confirmed"}>Sign and generate QR <span>&#8594;</span></button>
              {error && <p className="presentation-error">{error}</p>}
            </section>
            <section className="qr-result">
              {qrData ? <>
                <img src={qrData} alt="Signed VeriBind presentation QR code" />
                <strong>Scan to verify {selectedField}</strong>
                <small>{presentation?.challengeSignature ? "Fresh challenge signed · wallet controlled · no file shared" : "Presentation signed · use a fresh verifier challenge for replay resistance"}</small>
              </> : (
                <div className="qr-empty">
                  <span>QR</span>
                  <p>{status !== "Confirmed" ? "Your credential must be Confirmed first." : "Connect the holder wallet, then sign to create your QR."}</p>
                </div>
              )}
            </section>
          </>
        )}
      </div>
      {mode === "qr" && presentation && <div className="presentation-payload"><span>Signed presentation</span><code>hash {presentation.signedHash.slice(0, 18)}... · nonce {presentation.nonce.slice(0, 12)}...</code></div>}
    </div>
  );
}

function Verifier({
  minted,
  status,
  holder,
  field,
  setField,
  proofRequested,
  setProofRequested,
  proofSent,
  setProofSent,
  proofDenied,
  setProofDenied,
  proofRequestRecipient,
  setProofRequestRecipient,
}: {
  minted: boolean;
  status: Status;
  holder: DemoHolder;
  field: string;
  setField: (value: string) => void;
  proofRequested: boolean;
  setProofRequested: (value: boolean) => void;
  proofSent: boolean;
  setProofSent: (value: boolean) => void;
  proofDenied: boolean;
  setProofDenied: (value: boolean) => void;
  proofRequestRecipient: string;
  setProofRequestRecipient: (value: string) => void;
}) {
  const [activeTab, setActiveTab] = useState<"request" | "scan">("request");
  const [publicAddress, setPublicAddress] = useState(proofRequestRecipient);
  const [addressError, setAddressError] = useState("");
  return (
    <div className="workspace">
      <div className="verify-intro">
        <span className="eyebrow">PHASE 03 / NO FILE SHARED</span>
        <h2>Ask for one fact. Nothing else.</h2>
        <p>
          The verifier can request a field only after the holder confirms the
          credential. The holder must then approve the response.
        </p>
      </div>
      <div className="verification-tabs" role="tablist" aria-label="Verification workflow">
        <button type="button" role="tab" aria-selected={activeTab === "request"} className={activeTab === "request" ? "active" : ""} onClick={() => setActiveTab("request")}>Request</button>
        <button type="button" role="tab" aria-selected={activeTab === "scan"} className={activeTab === "scan" ? "active" : ""} onClick={() => setActiveTab("scan")}>Scan QR</button>
      </div>
      {activeTab === "request" ? <>
      {proofRequested && <div className="verification-request-status"><strong>Request sent</strong><span>{field} claim · recipient {proofRequestRecipient} · waiting for holder approval</span></div>}
      <div className="verify-grid">
        <section className="request-card">
          <div className="card-heading">
            <div>
              <span className="eyebrow">VERIFIER REQUEST</span>
              <h3>Choose a field</h3>
            </div>
            <span className="request-number">01</span>
          </div>
          <label className="field-label">
            Public wallet address
            <input value={publicAddress} onChange={(event) => { setPublicAddress(event.target.value); setAddressError(""); }} placeholder="0x..." autoComplete="off" spellCheck={false} />
          </label>
          <p className="request-delivery-note">Demo notification only. Cross-device wallet delivery is not configured.</p>
          <label className="field-label">
            Requested claim
            <select
              value={field}
              onChange={(event) => {
                setField(event.target.value);
                setProofRequested(false);
                setProofSent(false);
                setProofDenied(false);
              }}
            >
              <option>Name</option>
              <option>Credential</option>
              <option>Institution</option>
              <option>Issued</option>
              <option>Photo hash</option>
            </select>
          </label>
          <div className="request-details">
            <div>
              <span>Credential</span>
              <strong>#001 · {holder.name}</strong>
            </div>
            <div>
              <span>Recipient status</span>
              <StatusPill status={status} />
            </div>
          </div>
          <button
            className="primary-action"
            onClick={() => {
              const recipient = publicAddress.trim();
              if (!isRealWalletAddress(recipient)) {
                setAddressError("Enter a valid public wallet address.");
                return;
              }
              setAddressError("");
              setProofRequestRecipient(recipient);
              setProofSent(false);
              setProofDenied(false);
              setProofRequested(true);
              setActiveTab("scan");
            }}
            disabled={!minted || status !== "Confirmed" || proofRequested}
          >
            {!minted
              ? "Waiting for issuer to mint"
              : status !== "Confirmed"
              ? "Waiting for holder confirmation"
              : proofRequested
              ? "Request sent to holder"
              : "Ask the holder for proof"}
            <span>→</span>
          </button>
          {addressError && <p className="presentation-error">{addressError}</p>}
        </section>
        <section className="proof-card">
          <div className="card-heading">
            <div>
              <span className="eyebrow">HOLDER RESPONSE</span>
              <h3>
                {proofDenied
                  ? "Holder denied this request"
                  : proofSent
                  ? "Holder shared the proof"
                  : proofRequested
                  ? "Awaiting holder approval"
                  : "No request yet"}
              </h3>
            </div>
            <span className="proof-icon">{proofDenied ? "!" : proofSent ? "✓" : "···"}</span>
          </div>
          {proofDenied ? (
            <div className="denied-result"><strong>Request denied</strong><p>The holder chose not to share this field. No proof was received.</p></div>
          ) : proofSent ? (
            <div className="match-result">
              <span className="match-check">✓</span>
              <div>
                <strong>Ready to verify</strong>
                <p>The holder approved sharing {field}. Scan their signed QR to verify the signature and Merkle proof.</p>
                <button className="secondary-action" onClick={() => setActiveTab("scan")}>Open QR verification</button>
              </div>
            </div>
          ) : (
            <div className="waiting-state">
              <div className="waiting-lines">
                <span />
                <span />
                <span />
              </div>
              <p>
                {proofRequested
                  ? "The holder must open Review and explicitly share this proof."
                  : "Send a request after the holder confirms the credential."}
              </p>
            </div>
          )}
        </section>
      </div>
      <div className="privacy-strip">
        <span className="shield">+</span>
        <div>
          <strong>Zero document disclosure</strong>
          <span>
            No certificate, CID plaintext, AES key, or private key is included.
          </span>
        </div>
        <span className="proof-spec">SHA-256 · Merkle v1</span>
      </div>
      </> : <>
        {proofRequested && <div className="verification-request-status"><strong>Request sent to {proofRequestRecipient}</strong><span>After the holder approves, scan or import their signed QR below to verify the {field} claim.</span></div>}
        <QrVerifier />
      </>}
    </div>
  );
}

const approvedOrganizations = [
  { id: "ORG-001", name: "Example University", credential: "degree-certificate" },
  { id: "ORG-002", name: "Northstar Bank", credential: "identity-certificate" },
  { id: "ORG-003", name: "State Transport Authority", credential: "identity-certificate" },
];

function OrganizationShareCard({ minted, holder, request, response, onCreate }: { minted: boolean; holder: DemoHolder; request: ConsentRequest | null; response: ConsentResponse | null; onCreate: (request: ConsentRequest) => void }) {
  const [organizationId, setOrganizationId] = useState(approvedOrganizations[0].id);
  const [purpose, setPurpose] = useState("Admission verification");
  const [expiryHours, setExpiryHours] = useState("24");
  const [requestedFields, setRequestedFields] = useState(["Name", "Credential"]);
  const organization = approvedOrganizations.find((candidate) => candidate.id === organizationId) ?? approvedOrganizations[0];
  const toggleField = (value: string) => setRequestedFields((current) => current.includes(value) ? current.filter((fieldName) => fieldName !== value) : [...current, value]);
  const create = () => {
    if (!requestedFields.length) return;
    onCreate({ type: "veribind-verification-request", version: 1, requestId: `req-${randomNonce()}`, organizationId: organization.id, organizationName: organization.name, requestedCredential: organization.credential, requestedFields, purpose, expiresAt: Math.floor(Date.now() / 1000) + Number(expiryHours) * 3600, nonce: randomNonce(), status: "Pending" });
  };
  return <section className="organization-share-card"><div className="mode-heading"><span className="eyebrow">ORGANIZATION REQUEST</span><h3>Send to an approved organization</h3><p>The organization receives a request notification. Your wallet signs only after you review its purpose and fields.</p></div><label className="field-label">Organization<select value={organizationId} onChange={(event) => setOrganizationId(event.target.value)}>{approvedOrganizations.map((candidate) => <option key={candidate.id} value={candidate.id}>{candidate.name}</option>)}</select></label><label className="field-label">Purpose<input value={purpose} onChange={(event) => setPurpose(event.target.value)} /></label><label className="field-label">Expires in<select value={expiryHours} onChange={(event) => setExpiryHours(event.target.value)}><option value="24">24 hours</option><option value="72">3 days</option><option value="168">7 days</option></select></label><div className="request-field-options"><span className="eyebrow">FIELDS TO DISCLOSE</span>{["Name", "Credential", "Institution", "Issued"].map((value) => <label key={value}><input type="checkbox" checked={requestedFields.includes(value)} onChange={() => toggleField(value)} />{value}</label>)}</div><div className="share-recipient"><span>Credential</span><strong>{holder.credential}</strong></div><button className="primary-action" onClick={create} disabled={!minted || !requestedFields.length || Boolean(request?.status === "Pending")}>Create consent request <span>→</span></button>{request && <div className={`request-status ${response ? "approved" : request.status.toLowerCase()}`}><strong>{response ? "Signed response ready" : `Request ${request.status}`}</strong><span>{response ? `Bound to ${organization.name}` : `${request.requestedFields.join(", ")} · expires ${new Date(request.expiresAt * 1000).toLocaleDateString()}`}</span></div>}</section>;
}

function QrVerifier() {
  const [raw, setRaw] = useState("");
  const [result, setResult] = useState<{ valid: boolean; reason?: string; presentation?: VeribindPresentation; challenge?: VerificationChallenge } | null>(null);
  const [challengePayload, setChallengePayload] = useState<VerificationChallenge | null>(null);
  const [challengeQr, setChallengeQr] = useState("");
  const [isVerifying, setIsVerifying] = useState(false);
  const validate = async (value: string) => {
    if (!value.trim()) {
      setResult({ valid: false, reason: "Scan a QR or paste its presentation payload first." });
      return;
    }
    setIsVerifying(true);
    setResult(null);
    try {
      const presentation = JSON.parse(value) as VeribindPresentation;
      if (!window.ethereum) throw new Error("Live blockchain status unavailable");
      const provider = new BrowserProvider(window.ethereum as never);
      const network = await provider.getNetwork();
      if (Number(network.chainId) !== presentationChainId) throw new Error("Wrong network");
      const contract = new Contract(presentationContract, credentialReadAbi, provider);
      const tokenId = presentation.tokenId;
      const holderTokenCount = Number(await contract.holderCredentialCount(presentation.recipientAddress));
      const holderTokenIds = await Promise.all(Array.from({ length: holderTokenCount }, (_, index) => contract.holderCredentialAt(presentation.recipientAddress, index) as Promise<bigint>));
      if (!holderTokenIds.some((candidate) => candidate.toString() === tokenId)) throw new Error("This token is not registered to the presented wallet address");
      const statusNames = ["Pending", "Confirmed", "Disputed"] as const;
      const status = statusNames[Number(await contract.credentialStatus(tokenId))] ?? "Disputed";
      const chain = { chainId: presentationChainId, contractAddress: presentationContract, recipientAddress: await contract.credentialRecipient(tokenId), tokenId, status, certificateMerkleRoot: await contract.credentialMerkleRoot(tokenId), photoHash: await contract.credentialPhotoHash(tokenId), issuanceDigest: await contract.credentialIssuanceDigest(tokenId), issuedAt: Number(await contract.credentialIssuedAt(tokenId)), expiresAt: Number(await contract.credentialExpiresAt(tokenId)) } as const;
      const authenticity = await checkPresentation(presentation, chain);
      if (authenticity.valid && challengePayload) {
        const challengeResult = checkVerificationChallenge(presentation, challengePayload);
        setResult({ ...challengeResult, presentation, challenge: challengePayload });
      } else {
        setResult({ ...authenticity, presentation });
      }
    } catch (reason) {
      setResult({ valid: false, reason: reason instanceof Error ? reason.message : "Live blockchain status unavailable" });
    } finally {
      setIsVerifying(false);
    }
  };
  const createChallenge = async () => {
    if (!result?.presentation) return;
    const presentation = result.presentation;
    const challenge: VerificationChallenge = {
      challenge: randomNonce(),
      chainId: presentation.chainId,
      contractAddress: presentation.contractAddress,
      tokenId: presentation.tokenId,
      recipientAddress: presentation.recipientAddress,
      certificateMerkleRoot: presentation.certificateMerkleRoot,
      requestedFields: presentation.disclosures.map((disclosure) => disclosure.fieldName),
      issuedAt: Math.floor(Date.now() / 1000),
      expiresAt: Math.floor(Date.now() / 1000) + 120,
    };
    setChallengePayload(challenge);
    setResult({ ...result, challenge });
    setChallengeQr(await QRCode.toDataURL(JSON.stringify(challenge), { width: 280, margin: 2, errorCorrectionLevel: "M" }));
  };
  const importQr = (file: File) => {
    const reader = new FileReader();
    reader.onload = () => {
      const image = new Image();
      image.onload = () => {
        const canvas = document.createElement("canvas");
        canvas.width = image.width;
        canvas.height = image.height;
        const context = canvas.getContext("2d");
        if (!context) return;
        context.drawImage(image, 0, 0);
        const pixels = context.getImageData(0, 0, image.width, image.height);
        const decoded = jsQR(pixels.data, pixels.width, pixels.height);
        if (decoded) {
          setRaw(decoded.data);
          setResult(null);
        } else {
          setResult({ valid: false, reason: "QR code could not be read" });
        }
      };
      image.src = String(reader.result);
    };
    reader.readAsDataURL(file);
  };
  return (
    <section className="qr-verifier">
      <div className="card-heading">
        <div><span className="eyebrow">VERIFIER / IMPORT PRESENTATION</span><h3>Scan a holder QR</h3></div>
        <span className="request-number">LIVE CHECK</span>
      </div>
      <p className="qr-verifier-copy">Import or paste the signed presentation, verify the live credential first, then issue a fresh wallet challenge before accepting control of the credential.</p>
      <div className="qr-import-row">
        <label className="qr-file-label">Choose QR image<input type="file" accept="image/*" onChange={(event) => { const file = event.target.files?.[0]; if (file) importQr(file); }} /></label>
        <button className="primary-action" onClick={() => void validate(raw)} disabled={!raw.trim() || isVerifying}>{isVerifying ? "Verifying..." : "Verify presentation"}</button>
      </div>
      <textarea value={raw} onChange={(event) => { setRaw(event.target.value); setResult(null); setChallengePayload(null); }} placeholder="Or paste the signed QR payload here" />
      {result && <div className={`qr-validation ${result.valid ? "valid" : "invalid"}`}><strong>{result.valid ? "CRYPTographic CHECK PASSED" : "NOT VERIFIED"}</strong><span>{result.valid ? result.challenge ? "Fresh challenge, wallet signature, live status, recipient, Merkle root, and proof passed." : "Credential authenticity and the holder's presentation signature passed. Issue a fresh challenge before relying on wallet control." : result.reason}</span></div>}
      {result?.presentation && result.valid && <div className="verification-stages">
        <div className="verification-stage verified"><strong>GREEN · Credential data authentic</strong><span>Official contract, chain, Confirmed status, issuer-bound root, recipient, and Merkle proof passed.</span></div>
        <div className={`verification-stage ${result.challenge ? result.valid ? "verified" : "pending" : "pending"}`}><strong>{result.challenge && result.valid ? "GREEN · Presenter controls credential wallet" : "YELLOW · Fresh wallet challenge required"}</strong><span>{result.challenge && result.valid ? "The recipient wallet signed this verifier session's challenge." : "Generate a fresh challenge and have the recipient sign it. A static QR can be copied."}</span>{!result.challenge && <button className="secondary-action" onClick={createChallenge}>Generate fresh challenge</button>}</div>
        <div className="verification-stage caution"><strong>YELLOW · Physical identity comparison required</strong><span>Compare the disclosed name and photo with the person physically present. Blockchain does not prove this match.</span></div>
        <div className="verification-disclosures"><span className="eyebrow">DISCLOSED FOR HUMAN COMPARISON</span>{result.presentation.disclosures.map((disclosure) => <div key={`${disclosure.fieldName}-${disclosure.fieldIndex}`}><span>{disclosure.fieldName}</span><strong>{disclosure.fieldValue}</strong></div>)}</div>
        {challengePayload && <div className="challenge-handoff"><div><span className="eyebrow">VERIFIER CHALLENGE</span><strong>Show this QR to the holder</strong><p>The holder scans it, signs with the matching wallet, and returns a response QR.</p>{challengeQr && <img src={challengeQr} alt="Fresh verifier challenge QR code" />}<small>Expires {new Date(challengePayload.expiresAt * 1000).toLocaleTimeString()}</small></div><label className="field-label challenge-output">JSON fallback<textarea readOnly value={JSON.stringify(challengePayload, null, 2)} /></label></div>}
      </div>}
    </section>
  );
}

function Debug({
  status,
  registered,
  approved,
  minted,
  proofRequested,
  proofSent,
  proofDenied,
  field,
  walletAddress,
  chainCredential,
}: {
  status: Status;
  registered: boolean;
  approved: number;
  minted: boolean;
  proofRequested: boolean;
  proofSent: boolean;
  proofDenied: boolean;
  field: string;
  walletAddress: string;
  chainCredential: { tokenId: string; merkleRoot: string; issuanceDigest: string; expiresAt: number } | null;
}) {
  const [chainCheckVersion, setChainCheckVersion] = useState(0);
  const [chainDiagnostics, setChainDiagnostics] = useState({
    connection: "Checking",
    chainId: "—",
    blockNumber: "—",
    localNode: "Checking",
    contract: "Checking",
    contractAddress: presentationContract,
  });

  useEffect(() => {
    let active = true;
    const inspectChain = async () => {
      const disconnected = {
        connection: "Unavailable",
        chainId: "—",
        blockNumber: "—",
        localNode: "Unknown",
        contract: "Unknown",
        contractAddress: presentationContract,
      };
      try {
        if (!window.ethereum) throw new Error("MetaMask unavailable");
        const provider = new BrowserProvider(window.ethereum as never);
        const network = await provider.getNetwork();
        const blockNumber = await provider.getBlockNumber();
        const chainId = Number(network.chainId);
        let contract = "Not configured";
        if (isRealWalletAddress(presentationContract) && !/^0x0{40}$/i.test(presentationContract)) {
          if (chainId !== presentationChainId) {
            contract = `Wrong network (expected ${presentationChainId})`;
          } else {
            const code = await provider.getCode(presentationContract);
            contract = code === "0x" ? "No contract deployed at this address" : "Deployed";
          }
        }
        if (active) setChainDiagnostics({
          connection: "Reachable",
          chainId: String(chainId),
          blockNumber: String(blockNumber),
          localNode: chainId === 31337 ? "Connected (Hardhat 31337)" : `Not selected (current chain ${chainId})`,
          contract,
          contractAddress: presentationContract,
        });
      } catch {
        if (active) setChainDiagnostics(disconnected);
      }
    };
    void inspectChain();
    const interval = window.setInterval(() => void inspectChain(), 10000);
    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, [chainCheckVersion]);

  const flowSteps = [
    {
      stage: "01",
      label: "Identity",
      type: "Wallet-bound registration",
      state: registered ? "Registered" : "Waiting",
      tone: registered ? "complete" : "waiting",
      detail: registered ? "DID and doc hash bound to wallet" : "No holder identity yet",
    },
    {
      stage: "02",
      label: "Institution",
      type: "Issue approval flow",
      state: minted ? "Minted" : approved >= 3 ? "Ready to mint" : `${approved}/3 approvals`,
      tone: minted ? "complete" : approved >= 3 ? "active" : "waiting",
      detail: minted ? "NFT issued and activated" : "Threshold approvals pending",
    },
    {
      stage: "03",
      label: "Holder review",
      type: "Credential consent",
      state: status,
      tone:
        status === "Confirmed"
          ? "complete"
          : status === "Disputed"
          ? "danger"
          : "active",
      detail:
        status === "Confirmed"
          ? "Holder accepted the credential"
          : status === "Disputed"
          ? "Holder rejected issuance"
          : "Waiting on holder decision",
    },
    {
      stage: "04",
      label: "Selective proof",
      type: "Field-level verifiable share",
      state: proofDenied
        ? "Denied"
        : proofSent
        ? "Shared and verified"
        : proofRequested
        ? "Awaiting response"
        : "Not requested",
      tone: proofDenied ? "danger" : proofSent ? "complete" : proofRequested ? "active" : "waiting",
      detail: proofDenied ? "Verifier request denied by holder" : proofSent ? "Minimal claim delivered" : "No proof shared yet",
    },
  ];

  const values = [
    ["Wallet address", walletAddress, "Connected holder or verifier wallet"],
    ["Role flow", "Holder / Issuer / Verifier", "RBAC route map"],
    ["DID", `did:veribind:${walletAddress.slice(2, 10)}`, "Wallet-linked identity"],
    ["docHash", registered ? "0x8bd4f2c1...e91c" : "Not registered", "User identity anchor"],
    ["Credential field", field, "Currently requested proof field"],
    ["Credential ID", chainCredential ? `#${chainCredential.tokenId}` : minted ? "#001 (demo)" : "Not minted", "Soulbound certificate ID"],
    ["Merkle root", chainCredential?.merkleRoot ?? (minted ? "0x6a1f2e8c...d440 (demo)" : "Pending generation"), "Certificate field root"],
    ["Issuance digest", chainCredential?.issuanceDigest ?? "Demo-local", "On-chain issuance record digest"],
    ["Credential expiry", chainCredential?.expiresAt ? new Date(chainCredential.expiresAt * 1000).toISOString() : "No expiry", "Read from the deployed contract"],
    ["Issuer approvals", `${approved}/5 (threshold 3)`, "Exact issuance tuple"],
    ["Lifecycle", status, "Contract status"],
    ["Proof request", proofRequested ? "Requested" : "Idle", "Verifier side request state"],
    ["Proof status", proofDenied ? "Denied" : proofSent ? "Shared" : "Not shared", "Holder response"],
  ];

  return (
    <div className="debug-workspace">
      <div className="debug-intro">
        <div>
          <span className="eyebrow">LOCAL ONLY / SYNTHETIC DATA</span>
          <h2>Trace the full credential flow</h2>
          <p>
            Follow each wallet-driven state transition from registration to proof
            sharing, and inspect the exact values the verifier checks before trust is granted.
          </p>
        </div>
        <span className="debug-badge">DEBUG MODE</span>
      </div>

      <div className="debug-flow-panel">
        <div className="debug-section-heading">
          <div>
            <span className="eyebrow">FLOW TYPE</span>
            <h3>Credential lifecycle map</h3>
          </div>
          <span className="debug-refresh">wallet-rbac</span>
        </div>

        <div className="debug-flow">
          {flowSteps.map((step, index) => (
            <div className="debug-flow-step-wrap" key={step.stage}>
              <div className={`debug-flow-step ${step.tone}`}>
                <span className="debug-flow-index">{step.stage}</span>
                <div className="debug-flow-copy">
                  <strong>{step.label}</strong>
                  <small>{step.type}</small>
                </div>
                <span className={`debug-flow-status ${step.tone}`}>{step.state}</span>
              </div>
              {index < flowSteps.length - 1 && <span className="debug-flow-connector" />}
            </div>
          ))}
        </div>
      </div>

      <section className="debug-values">
        <div className="debug-section-heading">
          <div>
            <span className="eyebrow">NETWORK DIAGNOSTICS</span>
            <h3>Blockchain and contract status</h3>
          </div>
          <button className="debug-refresh" onClick={() => setChainCheckVersion((version) => version + 1)}>Refresh status</button>
        </div>
        <div className="debug-table">
          {[
            ["Wallet RPC", chainDiagnostics.connection, "MetaMask provider responds to network and block queries"],
            ["Selected chain ID", chainDiagnostics.chainId, "Hardhat local network uses 31337"],
            ["Latest block", chainDiagnostics.blockNumber, "Latest block visible to this wallet provider"],
            ["Local Hardhat node", chainDiagnostics.localNode, "Reachability is checked through the selected MetaMask network"],
            ["Contract deployment", chainDiagnostics.contract, "Bytecode check at the configured chain and address"],
            ["Configured contract ID", chainDiagnostics.contractAddress, "VITE_VERIBIND_CONTRACT_ADDRESS"],
          ].map(([label, value, detail]) => (
            <div className="debug-row" key={label}>
              <span>{label}<small>{detail}</small></span>
              <code>{value}</code>
            </div>
          ))}
        </div>
      </section>

      <section className="debug-values">
        <div className="debug-section-heading">
          <div>
            <span className="eyebrow">RUNTIME VALUES</span>
            <h3>Hashes, addresses & IDs</h3>
          </div>
          <span className="debug-refresh">fixture-v1</span>
        </div>
        <div className="debug-table">
          {values.map(([label, value, detail]) => (
            <div className="debug-row" key={label}>
              <span>
                {label}
                <small>{detail}</small>
              </span>
              <code>{String(value)}</code>
              <button
                className="copy-button"
                onClick={() => navigator.clipboard?.writeText(String(value))}
              >
                Copy
              </button>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

function Empty({ title, text }: { title: string; text: string }) {
  return (
    <div className="empty-state">
      <span className="eyebrow">WORKFLOW PAUSED</span>
      <h2>{title}</h2>
      <p>{text}</p>
    </div>
  );
}
function PanelTitle({ title, eyebrow }: { title: string; eyebrow: string }) {
  return (
    <div className="panel-title">
      <span className="eyebrow">{eyebrow}</span>
      <h3>{title}</h3>
    </div>
  );
}
function Boundary({ label, value }: { label: string; value: string }) {
  return (
    <div className="boundary-item">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
function StatusPill({ status }: { status: Status }) {
  return (
    <span className={`status-pill ${status.toLowerCase()}`}>
      <span /> {status}
    </span>
  );
}

export default App;
