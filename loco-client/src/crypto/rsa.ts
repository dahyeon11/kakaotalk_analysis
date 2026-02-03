import { publicEncrypt, constants } from "node:crypto";

/**
 * RSA-OAEP encrypt with SHA1.
 * Used for encType=15 (older protocol).
 */
export function rsaEncryptOAEP(
  plaintext: Buffer,
  publicKeyPem: string,
): Buffer {
  return publicEncrypt(
    {
      key: publicKeyPem,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha1",
    },
    plaintext,
  );
}

/**
 * RSA encrypt with PKCS1v1.5 padding.
 * Used for encType=16 (current KakaoTalk protocol).
 */
export function rsaEncryptPKCS1(
  plaintext: Buffer,
  publicKeyPem: string,
): Buffer {
  return publicEncrypt(
    {
      key: publicKeyPem,
      padding: constants.RSA_PKCS1_PADDING,
    },
    plaintext,
  );
}

/**
 * Convert a raw base64 public key (no PEM headers) into PEM format.
 */
export function toPem(base64Key: string): string {
  const lines: string[] = [];
  for (let i = 0; i < base64Key.length; i += 64) {
    lines.push(base64Key.slice(i, i + 64));
  }
  return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----\n`;
}
