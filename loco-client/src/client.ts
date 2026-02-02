import { LocoSocket } from "./net/index.ts";
import type {
  LocoClientConfig,
  LoginCredentials,
  LocoPacketHeader,
  DEFAULT_CONFIG,
} from "./types/index.ts";

export interface ChatMessage {
  chatId: number;
  msgId: number;
  message: string;
  type: number;
  sender?: number;
}

export class LocoClient {
  private socket: LocoSocket;
  private config: LocoClientConfig;
  private credentials: LoginCredentials;

  /** Callback for incoming messages */
  onMessage?: (msg: ChatMessage) => void;

  /** Callback for any incoming packet (for debugging/analysis) */
  onPacket?: (
    header: LocoPacketHeader,
    body: Record<string, unknown>,
  ) => void;

  constructor(config: LocoClientConfig, credentials: LoginCredentials) {
    this.config = config;
    this.credentials = credentials;
    this.socket = new LocoSocket(config);

    this.socket.on("packet", (header, body) => {
      this.onPacket?.(header, body);
      if (header.command === "MSG") {
        this.handleMsg(body);
      }
    });

    this.socket.on("error", (err) => {
      console.error("[LocoClient] Socket error:", err.message);
    });

    this.socket.on("close", () => {
      console.log("[LocoClient] Connection closed.");
    });
  }

  /** Full login sequence: connect → handshake → GETTOKEN → CHECKIN → LOGINLIST */
  async login(): Promise<Record<string, unknown>> {
    console.log(
      `[LocoClient] Connecting to ${this.config.host}:${this.config.port}...`,
    );
    await this.socket.connect();
    console.log("[LocoClient] Handshake complete.");

    // Step 1: GETTOKEN
    console.log("[LocoClient] Sending GETTOKEN...");
    const tokenResp = await this.socket.request("GETTOKEN", {
      ts: [2, 3, 11, 12, 4, 9, 10, 15],
    });
    console.log("[LocoClient] GETTOKEN response:", tokenResp.body);

    // Step 2: CHECKIN
    console.log("[LocoClient] Sending CHECKIN...");
    const checkinResp = await this.socket.request("CHECKIN", {
      MCCMNC: this.credentials.mccmnc,
      appVer: this.credentials.appVer,
      lang: this.credentials.lang,
      ntype: 3,
      os: "android",
      userId: this.credentials.userId,
    });
    console.log("[LocoClient] CHECKIN response:", checkinResp.body);

    // Step 3: LOGINLIST
    console.log("[LocoClient] Sending LOGINLIST...");
    const loginResp = await this.socket.request("LOGINLIST", {
      oauthToken: this.credentials.oauthToken,
      duuid: this.credentials.duuid,
      appVer: this.credentials.appVer,
      os: "android",
      MCCMNC: this.credentials.mccmnc,
      lang: this.credentials.lang,
      ntype: 3,
      chatIds: [],
      maxIds: [],
      lastTokenId: 0,
      lbk: 0,
      bg: false,
      revision: 0,
      prtVer: "1",
      rp: Buffer.from([0x01, 0x00, 0xff, 0xff, 0x01, 0x00]),
    });
    console.log("[LocoClient] LOGINLIST response status:", loginResp.header.statusCode);

    return loginResp.body;
  }

  /** Send a text message to a chat room. */
  async sendMessage(chatId: number, text: string): Promise<void> {
    await this.socket.request("WRITE", {
      msg: text,
      c: chatId,
      t: 1,
    });
  }

  /** Request message sync for a chat room. */
  async syncMessages(
    chatId: number,
    count: number = 20,
  ): Promise<Record<string, unknown>> {
    const resp = await this.socket.request("SYNCMSG", {
      chatId,
      cnt: count,
      cur: 0,
      max: 0,
    });
    return resp.body;
  }

  /** Listen for packets (keeps the connection alive). */
  listen(): void {
    console.log("[LocoClient] Listening for incoming packets...");
  }

  disconnect(): void {
    this.socket.disconnect();
  }

  // -- private --

  private handleMsg(body: Record<string, unknown>): void {
    const chatLog = body["chatLog"] as
      | Record<string, unknown>
      | undefined;
    if (!chatLog) return;

    const msg: ChatMessage = {
      chatId: body["chatId"] as number,
      msgId: chatLog["msgId"] as number,
      message: chatLog["message"] as string,
      type: chatLog["type"] as number,
      sender: chatLog["authorId"] as number | undefined,
    };

    this.onMessage?.(msg);
  }
}
