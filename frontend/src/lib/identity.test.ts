import { describe, expect, it } from "vitest";
import { extractDocumentName, fingerprintDocumentText, normalizeDocumentText } from "./identity";

describe("identity document scanning helpers", () => {
  it("normalizes OCR whitespace and unicode consistently", () => {
    expect(normalizeDocumentText("  NAME:  Ananya   Rao \n ID 1234 "))
      .toBe(normalizeDocumentText("name: ananya rao id 1234"));
  });

  it("extracts a labeled name from OCR lines", () => {
    expect(extractDocumentName("GOVERNMENT ID\nName: Ananya Rao\nDate of Birth: 01/01/2000"))
      .toBe("Ananya Rao");
    expect(extractDocumentName("नाम\nअनन्या राव\nपता"))
      .toBe("अनन्या राव");
  });

  it("rejects empty or unreadable OCR instead of hashing it", async () => {
    await expect(fingerprintDocumentText("   \n   ")).rejects.toThrow("Not enough readable document text");
  });

  it("produces a stable SHA-256 fingerprint for readable OCR text", async () => {
    const first = await fingerprintDocumentText("Name: Ananya Rao\nID number 123456789\nIssued 2026");
    const second = await fingerprintDocumentText("  NAME:  ANANYA   RAO ID number 123456789 Issued 2026 ");
    expect(first).toBe(second);
    expect(first).toMatch(/^[0-9a-f]{64}$/);
  });
});