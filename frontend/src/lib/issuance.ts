import { keccak256, toUtf8Bytes } from "ethers";
import { encryptDocument, type EncryptedDocument } from "./encryption";
import { buildMerkleRoot, hashField } from "./merkle";

export type CertificateRecord = {
  wallet_address: string;
  program: string;
  name: string;
  credential: string;
  institution: string;
  issued: string;
  photo?: string;
};

export type CredentialPackage = {
  walletAddress: string;
  program: string;
  fields: [string, string][];
  merkleRoot: string;
  photoHash: string;
  encryptedDocument: EncryptedDocument;
  ciphertextHash: string;
  cid: string;
  issuanceDigest: string;
  schemaVersion: number;
  expiresAt: number;
  cidIsPlaceholder: boolean;
};

const requiredFields = ["wallet_address", "program", "name", "credential", "institution", "issued"] as const;

export function isWalletAddress(value: string): boolean {
  return /^0x[0-9a-f]{40}$/i.test(value.trim());
}

export function validateCertificateRecord(input: Record<string, unknown>, expectedAddress: string): CertificateRecord {
  for (const field of requiredFields) {
    if (!(field in input)) throw new Error(`Missing required field: ${field}`);
    if (typeof input[field] !== "string") throw new Error(`Field ${field} must be a string.`);
    if (!String(input[field]).trim()) throw new Error(`Required field ${field} cannot be empty.`);
  }
  const walletAddress = String(input.wallet_address).trim();
  if (!isWalletAddress(walletAddress)) throw new Error("Field wallet_address must be a valid Ethereum address.");
  if (walletAddress.toLowerCase() !== expectedAddress.trim().toLowerCase()) {
    throw new Error("Field wallet_address does not match the student address.");
  }
  if ("photo" in input && input.photo !== undefined && typeof input.photo !== "string") {
    throw new Error("Field photo must be a string when provided.");
  }
  return {
    wallet_address: walletAddress,
    program: String(input.program).trim(),
    name: String(input.name).trim(),
    credential: String(input.credential).trim(),
    institution: String(input.institution).trim(),
    issued: String(input.issued).trim(),
    photo: typeof input.photo === "string" ? input.photo.trim() : undefined,
  };
}

export function parseCertificateUpload(text: string, fileName: string, expectedAddress: string): CertificateRecord {
  let input: Record<string, unknown>;
  if (fileName.toLowerCase().endsWith(".json")) {
    try {
      const parsed: unknown = JSON.parse(text);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("JSON root must be an object.");
      input = parsed as Record<string, unknown>;
    } catch (reason) {
      if (reason instanceof Error && reason.message !== "JSON root must be an object.") {
        throw new Error(`Malformed JSON upload: ${reason.message}`);
      }
      throw reason;
    }
  } else if (fileName.toLowerCase().endsWith(".csv")) {
    input = parseCsv(text);
  } else {
    throw new Error("Upload must be a .json or .csv file.");
  }
  return validateCertificateRecord(input, expectedAddress);
}

export async function buildCredentialPackage(record: CertificateRecord, cidConfig?: { apiUrl?: string; jwt?: string }): Promise<CredentialPackage> {
  const photoHash = record.photo ? keccak256(toUtf8Bytes(record.photo)) : "0x" + "00".repeat(32);
  const fields: [string, string][] = [
    ["name", record.name],
    ["program", record.program],
    ["credential", record.credential],
    ["institution", record.institution],
    ["issued", record.issued],
    ...(record.photo ? [["photo hash", photoHash] as [string, string]] : []),
  ];
  const leaves = await Promise.all(fields.map(([name, value]) => hashField(1, name, value)));
  const encryptedDocument = await encryptDocument(JSON.stringify(record));
  const ciphertextHash = keccak256(toUtf8Bytes(JSON.stringify(encryptedDocument)));
  const merkleRoot = `0x${await buildMerkleRoot(leaves)}`;
  const issuanceDigest = issuanceDigestFor(record.wallet_address, record.program);
  const uploadedCid = await uploadEncryptedDocument(encryptedDocument, cidConfig);
  return {
    walletAddress: record.wallet_address,
    program: record.program,
    fields,
    merkleRoot,
    photoHash,
    encryptedDocument,
    ciphertextHash,
    cid: uploadedCid.cid,
    issuanceDigest,
    schemaVersion: 1,
    expiresAt: 0,
    cidIsPlaceholder: uploadedCid.isPlaceholder,
  };
}

export function issuanceDigestFor(walletAddress: string, program: string): string {
  return keccak256(toUtf8Bytes(`veribind-program-v1|${walletAddress.toLowerCase()}|${program.trim().normalize("NFC")}`));
}

export function canBuildCredential(record: Record<string, unknown>, address: string, didRegistered: boolean): boolean {
  if (!didRegistered) return false;
  try {
    validateCertificateRecord(record, address);
    return true;
  } catch {
    return false;
  }
}

export function findDuplicateCredential(address: string, program: string, credentials: { tokenId: string; issuanceDigest: string }[]): string | null {
  const expected = issuanceDigestFor(address, program).toLowerCase();
  return credentials.find((credential) => credential.issuanceDigest.toLowerCase() === expected)?.tokenId ?? null;
}

async function uploadEncryptedDocument(document: EncryptedDocument, config?: { apiUrl?: string; jwt?: string }): Promise<{ cid: string; isPlaceholder: boolean }> {
  const apiUrl = config?.apiUrl?.trim();
  const jwt = config?.jwt?.trim();
  if (!apiUrl || !jwt) {
    const webCrypto = globalThis.crypto;
    if (!webCrypto?.getRandomValues) throw new Error("Web Crypto is unavailable. Cannot create a random demo CID.");
    const randomBytes = webCrypto.getRandomValues(new Uint8Array(16));
    const suffix = Array.from(randomBytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    return { cid: `ipfs://placeholder/demo-${suffix}`, isPlaceholder: true };
  }
  const response = await fetch(apiUrl, {
    method: "POST",
    headers: { Authorization: `Bearer ${jwt}`, "Content-Type": "application/json" },
    body: JSON.stringify({ pinataContent: document, pinataMetadata: { name: "veribind-encrypted-credential" } }),
  });
  if (!response.ok) throw new Error(`Encrypted document upload failed with HTTP ${response.status}.`);
  const payload = await response.json() as { IpfsHash?: string };
  if (!payload.IpfsHash) throw new Error("Encrypted document upload returned no IPFS CID.");
  return { cid: `ipfs://${payload.IpfsHash}`, isPlaceholder: false };
}

function parseCsv(text: string): Record<string, unknown> {
  const rows = text.trim().split(/\r?\n/).filter(Boolean).map(parseCsvLine);
  if (rows.length !== 2 || rows[0].length === 0) throw new Error("CSV upload must contain one header row and exactly one data row.");
  const headers = rows[0].map((header) => header.trim());
  const values = rows[1];
  if (headers.some((header) => !header)) throw new Error("CSV header names cannot be empty.");
  if (values.length !== headers.length) throw new Error("CSV data does not match the header column count.");
  return Object.fromEntries(headers.map((header, index) => [header, values[index]]));
}

function parseCsvLine(line: string): string[] {
  const values: string[] = [];
  let current = "";
  let quoted = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (character === '"' && line[index + 1] === '"' && quoted) {
      current += '"';
      index += 1;
    } else if (character === '"') {
      quoted = !quoted;
    } else if (character === "," && !quoted) {
      values.push(current);
      current = "";
    } else {
      current += character;
    }
  }
  if (quoted) throw new Error("CSV upload contains an unterminated quoted value.");
  values.push(current);
  return values;
}
