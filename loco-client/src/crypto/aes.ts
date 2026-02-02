import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from "node:crypto";

const GCM_ALGORITHM = "aes-128-gcm";

/** GCM nonce size in bytes */
export const NONCE_SIZE = 12;

/** GCM authentication tag size in bytes */
export const TAG_SIZE = 16;

/**
 * Encrypt with AES-128-GCM.
 * Returns ciphertext + 16-byte auth tag appended.
 */
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

/**
 * Decrypt AES-128-GCM. Input is ciphertext with 16-byte auth tag appended.
 */
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

export function generateAESKey(): Buffer {
  return randomBytes(16);
}

export function generateNonce(): Buffer {
  return randomBytes(NONCE_SIZE);
}
