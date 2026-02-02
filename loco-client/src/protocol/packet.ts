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
  aesEncryptCFB,
  aesDecryptCFB,
  generateIV,
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
  const iv = generateIV();
  const encrypted = aesEncryptCFB(locoPacket, aesKey, iv);

  const buf = Buffer.alloc(4 + 16 + encrypted.length);
  buf.writeUInt32LE(16 + encrypted.length, 0); // length = iv + payload
  iv.copy(buf, 4);
  encrypted.copy(buf, 20);

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

  const iv = data.subarray(4, 20);
  const payload = data.subarray(20, totalSize);
  const decrypted = aesDecryptCFB(payload, aesKey, iv);

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

  // handshake type = 15 (RSA-OAEP-SHA1), block cipher mode = 2 (AES/CFB)
  const buf = Buffer.alloc(4 + 4 + 4 + 2 + encryptedKey.length);
  buf.writeUInt32LE(HANDSHAKE_LENGTH, 0);
  buf.writeUInt32LE(15, 4); // encryption type
  buf.writeUInt32LE(2, 8); // block cipher mode (CFB)
  buf.writeUInt16LE(0, 12); // padding
  encryptedKey.copy(buf, 14);

  return buf;
}

export function isHandshakePacket(data: Buffer): boolean {
  if (data.length < 4) return false;
  return data.readUInt32LE(0) === HANDSHAKE_LENGTH;
}

// ---------------------------------------------------------------------------
// Stream reassembly helper
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
