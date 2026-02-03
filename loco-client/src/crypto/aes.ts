import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from "node:crypto";

const CFB_ALGORITHM = "aes-256-cfb";

/** CFB IV size in bytes */
export const IV_SIZE = 16;

/** AES-256 key size in bytes */
export const AES_KEY_SIZE = 32;

/**
 * Encrypt with AES-256-CFB.
 * Returns ciphertext only (no auth tag in CFB mode).
 */
export function aesEncryptCFB(
  plaintext: Buffer,
  key: Buffer,
  iv: Buffer,
): Buffer {
  const cipher = createCipheriv(CFB_ALGORITHM, key, iv);
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

/**
 * Decrypt AES-256-CFB.
 */
export function aesDecryptCFB(
  ciphertext: Buffer,
  key: Buffer,
  iv: Buffer,
): Buffer {
  const decipher = createDecipheriv(CFB_ALGORITHM, key, iv);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export function generateAESKey(): Buffer {
  return randomBytes(AES_KEY_SIZE); // 32 bytes for AES-256
}

export function generateIV(): Buffer {
  return randomBytes(IV_SIZE);
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
