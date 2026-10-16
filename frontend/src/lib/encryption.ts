export type EncryptedDocument = {
  ciphertext: string;
  iv: string;
  algorithm: "AES-GCM-256";
};

export async function encryptDocument(document: string): Promise<EncryptedDocument> {
  const webCrypto = globalThis.crypto;
  if (!webCrypto?.subtle || !webCrypto.getRandomValues) throw new Error("Web Crypto is unavailable. Open VeriBind through localhost or HTTPS.");
  const key = await webCrypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const iv = webCrypto.getRandomValues(new Uint8Array(12));
  const encrypted = await webCrypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(document));
  return { ciphertext: encode(encrypted), iv: encode(iv), algorithm: "AES-GCM-256" };
}

export async function decryptDocument(encrypted: EncryptedDocument, key: CryptoKey): Promise<string> {
  const webCrypto = globalThis.crypto;
  if (!webCrypto?.subtle) throw new Error("Web Crypto is unavailable. Open VeriBind through localhost or HTTPS.");
  const plaintext = await webCrypto.subtle.decrypt({ name: "AES-GCM", iv: decode(encrypted.iv) }, key, decode(encrypted.ciphertext));
  return new TextDecoder().decode(plaintext);
}

function encode(value: ArrayBuffer | Uint8Array): string {
  return btoa(String.fromCharCode(...new Uint8Array(value)));
}

function decode(value: string): ArrayBuffer {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0)).buffer as ArrayBuffer;
}
