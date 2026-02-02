import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const AES_ALGORITHM = "aes-128-cfb";

export function aesEncryptCFB(
  plaintext: Buffer,
  key: Buffer,
  iv: Buffer,
): Buffer {
  const cipher = createCipheriv(AES_ALGORITHM, key, iv);
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

export function aesDecryptCFB(
  ciphertext: Buffer,
  key: Buffer,
  iv: Buffer,
): Buffer {
  const decipher = createDecipheriv(AES_ALGORITHM, key, iv);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export function generateAESKey(): Buffer {
  return randomBytes(16);
}

export function generateIV(): Buffer {
  return randomBytes(16);
}
