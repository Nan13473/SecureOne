export type ProofStep = { hash: string; side: "left" | "right" };
export type MerkleProof = { index: number; steps: ProofStep[] };

export async function hashField(schemaVersion: number, fieldName: string, value: string): Promise<string> {
  return sha256(`veribind-field-v${schemaVersion}|${fieldName}|${value.trim().normalize("NFC")}`);
}

export async function buildMerkleRoot(leaves: string[]): Promise<string> {
  if (!leaves.length) throw new Error("Cannot build a Merkle tree without leaves");
  let level = leaves;
  while (level.length > 1) {
    const next: string[] = [];
    for (let index = 0; index < level.length; index += 2) {
      const right = level[index + 1] ?? level[index];
      next.push(await sha256(`veribind-node-v1|${level[index]}|${right}`));
    }
    level = next;
  }
  return level[0];
}

export async function buildMerkleProof(leaves: string[], index: number): Promise<MerkleProof> {
  if (!leaves.length || index < 0 || index >= leaves.length) throw new Error("Invalid Merkle proof index");
  const steps: ProofStep[] = [];
  let level = leaves;
  let currentIndex = index;
  while (level.length > 1) {
    const siblingIndex = currentIndex % 2 === 0 ? currentIndex + 1 : currentIndex - 1;
    steps.push({ hash: level[siblingIndex] ?? level[currentIndex], side: currentIndex % 2 === 0 ? "right" : "left" });
    const next: string[] = [];
    for (let offset = 0; offset < level.length; offset += 2) {
      const right = level[offset + 1] ?? level[offset];
      next.push(await sha256(`veribind-node-v1|${level[offset]}|${right}`));
    }
    currentIndex = Math.floor(currentIndex / 2);
    level = next;
  }
  return { index, steps };
}

export async function verifyMerkleProof(leaf: string, proof: MerkleProof, root: string): Promise<boolean> {
  let current = leaf;
  for (const step of proof.steps) {
    current = step.side === "left"
      ? await sha256(`veribind-node-v1|${step.hash}|${current}`)
      : await sha256(`veribind-node-v1|${current}|${step.hash}`);
  }
  return current === root;
}

async function sha256(value: string): Promise<string> {
  const webCrypto = globalThis.crypto;
  if (!webCrypto?.subtle) throw new Error("Web Crypto is unavailable. Open VeriBind through localhost or HTTPS.");
  const digest = await webCrypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
