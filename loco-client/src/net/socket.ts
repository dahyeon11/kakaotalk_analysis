import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { connect as netConnect, type Socket } from "node:net";
import { EventEmitter } from "node:events";
import { generateAESKey } from "../crypto/index.ts";
import {
  buildHandshakePacket,
  buildEncryptedPacket,
  buildLocoPacket,
  PacketReader,
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

export class LocoSocket extends EventEmitter<LocoSocketEvents> {
  private socket: TLSSocket | Socket | null = null;
  private aesKey: Buffer;
  private reader: PacketReader;
  private packetId = 1000;
  private config: LocoClientConfig;

  /** Map of pending request id -> resolve callback */
  private pending = new Map<
    number,
    (result: {
      header: LocoPacketHeader;
      body: Record<string, unknown>;
    }) => void
  >();

  constructor(config: LocoClientConfig) {
    super();
    this.config = config;
    this.aesKey = generateAESKey();
    this.reader = new PacketReader(this.aesKey);
  }

  /** Connect to the LOCO server and perform the handshake. */
  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const onConnect = () => {
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
        const packets = this.reader.feed(chunk);
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
    const encrypted = buildEncryptedPacket(inner, this.aesKey);

    return new Promise((resolve, reject) => {
      this.pending.set(id, resolve);
      this.socket!.write(encrypted, (err) => {
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
    const encrypted = buildEncryptedPacket(inner, this.aesKey);
    this.socket!.write(encrypted);
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
