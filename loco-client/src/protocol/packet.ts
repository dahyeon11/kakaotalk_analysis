import { BSON } from "bson";
import {
  LOCO_HEADER_SIZE,
  ENCRYPTED_HEADER_SIZE,
  HANDSHAKE_LENGTH,
  type LocoPacketHeader,
  type LocoCommand,
  type LocoHandshakeData,
} from "../types/index.ts";
import {
  aesEncryptGCM,
  aesDecryptGCM,
  generateNonce,
  NONCE_SIZE,
  rsaEncryptOAEP,
} from "../crypto/index.ts";

// ---------------------------------------------------------------------------
// LOCO inner packet (plaintext layer)
// ---------------------------------------------------------------------------

export function buildLocoPacket(
  id: number,
  command: LocoCommand,
  statusCode: number,
  body: Record<string, unknown>,
): Buffer {
  const bsonBody = Buffer.from(BSON.serialize(body));
  const buf = Buffer.alloc(LOCO_HEADER_SIZE + bsonBody.length);

  buf.writeUInt32LE(id, 0);
  buf.writeUInt16LE(statusCode, 4);

  // command: 11 bytes, null-padded
  const cmdBuf = Buffer.alloc(11, 0);
  cmdBuf.write(command, "utf-8");
  cmdBuf.copy(buf, 6);

  buf.writeInt8(0, 17); // bodyType = 0 (BSON)
  buf.writeInt32LE(bsonBody.length, 18);
  bsonBody.copy(buf, LOCO_HEADER_SIZE);

  return buf;
}

export function parseLocoPacket(
  data: Buffer,
): { header: LocoPacketHeader; body: Record<string, unknown> } | null {
  if (data.length < LOCO_HEADER_SIZE) return null;

  const id = data.readUInt32LE(0);
  const statusCode = data.readUInt16LE(4);
  const command = data
    .subarray(6, 17)
    .toString("utf-8")
    .replace(/\0/g, "") as LocoCommand;
  const bodyType = data.readInt8(17);
  const bodyLength = data.readInt32LE(18);

  const header: LocoPacketHeader = {
    id,
    statusCode,
    command,
    bodyType,
    bodyLength,
  };

  let body: Record<string, unknown> = {};
  if (bodyLength > 0 && data.length >= LOCO_HEADER_SIZE + bodyLength) {
    try {
      body = BSON.deserialize(
        data.subarray(LOCO_HEADER_SIZE, LOCO_HEADER_SIZE + bodyLength),
      ) as Record<string, unknown>;
    } catch {
      // body stays empty if BSON parsing fails
    }
  }

  return { header, body };
}

// ---------------------------------------------------------------------------
// Encrypted LOCO packet (network layer)
// ---------------------------------------------------------------------------

export function buildEncryptedPacket(
  locoPacket: Buffer,
  aesKey: Buffer,
): Buffer {
  const nonce = generateNonce();
  const encrypted = aesEncryptGCM(locoPacket, aesKey, nonce);

  // [length:4][nonce:12][ciphertext+tag]
  const buf = Buffer.alloc(4 + NONCE_SIZE + encrypted.length);
  buf.writeUInt32LE(NONCE_SIZE + encrypted.length, 0);
  nonce.copy(buf, 4);
  encrypted.copy(buf, 4 + NONCE_SIZE);

  return buf;
}

export function parseEncryptedPacket(
  data: Buffer,
  aesKey: Buffer,
): { decrypted: Buffer; consumed: number } | null {
  if (data.length < ENCRYPTED_HEADER_SIZE + 1) return null;

  const length = data.readUInt32LE(0);
  const totalSize = 4 + length;

  if (data.length < totalSize) return null; // fragmented

  const nonce = data.subarray(4, 4 + NONCE_SIZE);
  const payload = data.subarray(4 + NONCE_SIZE, totalSize);
  const decrypted = aesDecryptGCM(payload, aesKey, nonce);

  return { decrypted, consumed: totalSize };
}

// ---------------------------------------------------------------------------
// Handshake packet
// ---------------------------------------------------------------------------

export function buildHandshakePacket(
  aesKey: Buffer,
  serverPublicKeyPem: string,
): Buffer {
  const encryptedKey = rsaEncryptOAEP(aesKey, serverPublicKeyPem);

  // [keyLen:4][encType:4][blockMode:4][encKey:keyLen]
  const buf = Buffer.alloc(4 + 4 + 4 + encryptedKey.length);
  buf.writeUInt32LE(encryptedKey.length, 0); // RSA ciphertext length (256)
  buf.writeUInt32LE(15, 4); // encryption type (RSA-OAEP-SHA1)
  buf.writeUInt32LE(4, 8); // block cipher mode (AES/GCM)
  encryptedKey.copy(buf, 12);

  return buf;
}

export function isHandshakePacket(data: Buffer): boolean {
  if (data.length < 4) return false;
  return data.readUInt32LE(0) === HANDSHAKE_LENGTH;
}

// ---------------------------------------------------------------------------
// Plain (unencrypted) packet framing — used over TLS (booking, checkin)
// [length:4 LE][loco_packet:length]
// ---------------------------------------------------------------------------

/**
 * In plaintext mode (over TLS), LOCO packets are sent raw — no length prefix.
 * The packet itself contains bodyLength at offset 18, so we can frame it.
 */
export function buildPlainPacket(locoPacket: Buffer): Buffer {
  return locoPacket; // no wrapping needed
}

export class PlainPacketReader {
  private buffer: Buffer = Buffer.alloc(0);

  /** Append incoming data and yield all complete parsed packets.
   *  Framing: read LOCO header (22 bytes), then bodyLength bytes. */
  feed(
    chunk: Buffer,
  ): Array<{ header: LocoPacketHeader; body: Record<string, unknown> }> {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    const results: Array<{
      header: LocoPacketHeader;
      body: Record<string, unknown>;
    }> = [];

    while (this.buffer.length >= LOCO_HEADER_SIZE) {
      const bodyLength = this.buffer.readInt32LE(18);
      const totalSize = LOCO_HEADER_SIZE + bodyLength;
      if (this.buffer.length < totalSize) break;

      const payload = this.buffer.subarray(0, totalSize);
      const loco = parseLocoPacket(payload);
      if (loco) results.push(loco);

      this.buffer = this.buffer.subarray(totalSize);
    }

    return results;
  }
}

// ---------------------------------------------------------------------------
// Encrypted stream reassembly helper
// ---------------------------------------------------------------------------

export class PacketReader {
  private buffer: Buffer = Buffer.alloc(0);
  private aesKey: Buffer;

  constructor(aesKey: Buffer) {
    this.aesKey = aesKey;
  }

  /** Append incoming data and yield all complete parsed packets. */
  feed(
    chunk: Buffer,
  ): Array<{ header: LocoPacketHeader; body: Record<string, unknown> }> {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    const results: Array<{
      header: LocoPacketHeader;
      body: Record<string, unknown>;
    }> = [];

    while (this.buffer.length >= ENCRYPTED_HEADER_SIZE + 1) {
      const parsed = parseEncryptedPacket(this.buffer, this.aesKey);
      if (!parsed) break; // incomplete packet, wait for more data

      const loco = parseLocoPacket(parsed.decrypted);
      if (loco) results.push(loco);

      this.buffer = this.buffer.subarray(parsed.consumed);
    }

    return results;
  }
}
