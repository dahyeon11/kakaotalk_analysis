import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { connect as netConnect, type Socket } from "node:net";
import { EventEmitter } from "node:events";
import { generateAESKey } from "../crypto/index.ts";
import {
  buildHandshakePacket,
  buildEncryptedPacket,
  buildPlainPacket,
  buildLocoPacket,
  PacketReader,
  PlainPacketReader,
} from "../protocol/index.ts";
import type {
  LocoClientConfig,
  LocoCommand,
  LocoPacketHeader,
} from "../types/index.ts";

export interface LocoSocketEvents {
  packet: [header: LocoPacketHeader, body: Record<string, unknown>];
  error: [error: Error];
  close: [];
  connected: [];
}

export interface LocoSocketOptions {
  /**
   * When true, packets are sent/received as plain LOCO over TLS
   * (no RSA handshake, no AES encryption). Used for booking server.
   */
  plaintext?: boolean;
}

export class LocoSocket extends EventEmitter<LocoSocketEvents> {
  private socket: TLSSocket | Socket | null = null;
  private aesKey: Buffer;
  private encryptedReader: PacketReader;
  private plainReader: PlainPacketReader;
  private packetId = 1000;
  private config: LocoClientConfig;
  private plaintext: boolean;

  /** Map of pending request id -> resolve callback */
  private pending = new Map<
    number,
    (result: {
      header: LocoPacketHeader;
      body: Record<string, unknown>;
    }) => void
  >();

  constructor(config: LocoClientConfig, options?: LocoSocketOptions) {
    super();
    this.config = config;
    this.plaintext = options?.plaintext ?? false;
    this.aesKey = generateAESKey();
    this.encryptedReader = new PacketReader(this.aesKey);
    this.plainReader = new PlainPacketReader();
  }

  /** Connect to the LOCO server. Performs RSA handshake unless in plaintext mode. */
  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const onConnect = () => {
        if (this.plaintext) {
          // No handshake needed — TLS provides encryption
          this.emit("connected");
          resolve();
          return;
        }

        // Send handshake: RSA-encrypted AES key
        const handshake = buildHandshakePacket(
          this.aesKey,
          this.config.serverPublicKey,
        );
        this.socket!.write(handshake, (err) => {
          if (err) return reject(err);
          this.emit("connected");
          resolve();
        });
      };

      if (this.config.useTLS) {
        this.socket = tlsConnect(
          {
            host: this.config.host,
            port: this.config.port,
            rejectUnauthorized: true,
          },
          onConnect,
        );
      } else {
        this.socket = netConnect(
          { host: this.config.host, port: this.config.port },
          onConnect,
        );
      }

      this.socket.on("data", (chunk: Buffer) => {
        if (process.env["LOCO_DEBUG"]) {
          console.log(`[Socket] recv ${chunk.length} bytes: ${chunk.subarray(0, Math.min(64, chunk.length)).toString("hex")}`);
        }
        const reader = this.plaintext ? this.plainReader : this.encryptedReader;
        const packets = reader.feed(chunk);
        for (const pkt of packets) {
          // Resolve pending request if matched
          const resolver = this.pending.get(pkt.header.id);
          if (resolver) {
            this.pending.delete(pkt.header.id);
            resolver(pkt);
          }
          this.emit("packet", pkt.header, pkt.body);
        }
      });

      this.socket.on("error", (err) => {
        this.emit("error", err);
        reject(err);
      });

      this.socket.on("close", () => {
        this.emit("close");
      });
    });
  }

  /** Send a LOCO command and return a promise that resolves with the server's response. */
  async request(
    command: LocoCommand,
    body: Record<string, unknown>,
  ): Promise<{ header: LocoPacketHeader; body: Record<string, unknown> }> {
    const id = ++this.packetId;
    const inner = buildLocoPacket(id, command, 0, body);
    const packet = this.plaintext
      ? buildPlainPacket(inner)
      : buildEncryptedPacket(inner, this.aesKey);

    return new Promise((resolve, reject) => {
      if (process.env["LOCO_DEBUG"]) {
        console.log(`[Socket] send ${command} id=${id} ${packet.length} bytes: ${packet.subarray(0, Math.min(64, packet.length)).toString("hex")}`);
      }
      this.pending.set(id, resolve);
      this.socket!.write(packet, (err) => {
        if (err) {
          this.pending.delete(id);
          reject(err);
        }
      });
    });
  }

  /** Send a LOCO command without waiting for a specific response. */
  send(command: LocoCommand, body: Record<string, unknown>): number {
    const id = ++this.packetId;
    const inner = buildLocoPacket(id, command, 0, body);
    const packet = this.plaintext
      ? buildPlainPacket(inner)
      : buildEncryptedPacket(inner, this.aesKey);
    this.socket!.write(packet);
    return id;
  }

  disconnect(): void {
    this.socket?.destroy();
    this.socket = null;
  }

  get sessionKey(): Buffer {
    return this.aesKey;
  }
}
