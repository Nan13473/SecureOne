export type VerifiedIdentity = {
  sourceType: string;
  recordId: string;
  verifiedAt: string;
  adapterVersion: string;
  name: string;
  dateOfBirth: string;
  address: string;
  documentNumber: string;
};

export function canonicalizeIdentity(identity: VerifiedIdentity): string {
  return [
    "veribind-identity-v1",
    identity.name.trim().normalize("NFC"),
    identity.dateOfBirth,
    identity.address.trim().normalize("NFC"),
    identity.documentNumber.trim().normalize("NFC"),
    identity.sourceType,
    identity.recordId,
    identity.verifiedAt,
    identity.adapterVersion,
  ].join("|");
}

export async function computeDocHash(identity: VerifiedIdentity): Promise<string> {
  const bytes = new TextEncoder().encode(canonicalizeIdentity(identity));
  const webCrypto = globalThis.crypto;
  if (!webCrypto?.subtle) throw new Error("Web Crypto is unavailable. Open VeriBind through localhost or HTTPS.");
  const digest = await webCrypto.subtle.digest("SHA-256", bytes);
  return toHex(digest);
}

export function normalizeDocumentText(value: string): string {
  return value.normalize("NFKC").trim().toLowerCase().replace(/\s+/g, " ");
}

export function extractDocumentName(value: string): string | null {
  const lines = value.normalize("NFKC").split(/\r?\n/).map((line) => line.replace(/\s+/g, " ").trim()).filter(Boolean);
  const labelPattern = /^(?:full\s+name|name|नाम)\s*[:：\-]?\s*(.*)$/i;
  for (let index = 0; index < lines.length; index += 1) {
    const match = lines[index].match(labelPattern);
    if (!match) continue;
    const candidate = (match[1] || lines[index + 1] || "").split(/\s+(?:date of birth|dob|address|document no|id no)\b/i)[0].trim();
    if (candidate.length >= 2 && /[\p{L}]/u.test(candidate)) return candidate;
  }
  return null;
}

export async function fingerprintDocumentText(value: string): Promise<string> {
  const normalized = normalizeDocumentText(value);
  if (normalized.length < 16) throw new Error("Not enough readable document text was found. Use a clear, well-lit image and try again.");
  const webCrypto = globalThis.crypto;
  if (!webCrypto?.subtle) throw new Error("Web Crypto is unavailable. Open VeriBind through localhost or HTTPS.");
  const digest = await webCrypto.subtle.digest("SHA-256", new TextEncoder().encode(normalized));
  return toHex(digest);
}

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
