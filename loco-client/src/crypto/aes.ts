import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from "node:crypto";

/** AES-128 key size in bytes (confirmed by Frida capture) */
export const AES_KEY_SIZE = 16;

export function generateAESKey(): Buffer {
  return randomBytes(AES_KEY_SIZE); // 16 bytes for AES-128
}

// Legacy GCM functions kept for reference
const GCM_ALGORITHM = "aes-128-gcm";
export const NONCE_SIZE = 12;
export const TAG_SIZE = 16;

export function aesEncryptGCM(
  plaintext: Buffer,
  key: Buffer,
  nonce: Buffer,
): Buffer {
  const cipher = createCipheriv(GCM_ALGORITHM, key, nonce);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([encrypted, tag]);
}

export function aesDecryptGCM(
  ciphertextWithTag: Buffer,
  key: Buffer,
  nonce: Buffer,
): Buffer {
  const ciphertext = ciphertextWithTag.subarray(
    0,
    ciphertextWithTag.length - TAG_SIZE,
  );
  const tag = ciphertextWithTag.subarray(ciphertextWithTag.length - TAG_SIZE);

  const decipher = createDecipheriv(GCM_ALGORITHM, key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export function generateNonce(): Buffer {
  return randomBytes(NONCE_SIZE);
}
