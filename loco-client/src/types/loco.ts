/** Known LOCO commands */
export type LocoCommand =
  | "GETTOKEN"
  | "CHECKIN"
  | "LOGINLIST"
  | "WRITE"
  | "MSG"
  | "SYNCMSG"
  | "GETCONF"
  | "GETPK"
  | "GETLPK"
  | "SETPK"
  | "SETSK"
  | "SETST"
  | "SCREATE"
  | "SWRITE"
  | "CHATONROOM"
  | "ACTION"
  | "GETMEM"
  | "BLSYNC"
  | (string & {});

export interface LocoPacketHeader {
  /** Packet identifier (auto-incrementing, starts at 1000 / 0x3E8) */
  id: number;
  /** Status code (0 = request from client, response status from server) */
  statusCode: number;
  /** LOCO command name, max 11 bytes null-padded */
  command: LocoCommand;
  /** Body type (0 = BSON) */
  bodyType: number;
  /** Body payload length in bytes */
  bodyLength: number;
}

/** LOCO header is always 22 bytes */
export const LOCO_HEADER_SIZE = 22;

/** Encrypted packet: [length:4][iv:16][ciphertext] */
export const ENCRYPTED_HEADER_SIZE = 20; // 4 (length) + 16 (IV)

/** Handshake packet length field value */
export const HANDSHAKE_LENGTH = 256;

export interface LocoHandshakeData {
  /** Encryption type (16 = RSA variant used by KakaoTalk) */
  type: number;
  /** Block cipher mode (3 = AES-256-CFB) */
  blockCipherMode: number;
  /** RSA-encrypted AES key */
  payload: Buffer;
}

export interface LocoClientConfig {
  /** LOCO server host */
  host: string;
  /** LOCO server port */
  port: number;
  /** RSA public key of the server (PEM or base64) */
  serverPublicKey: string;
  /** Whether to use TLS for the initial TCP connection */
  useTLS: boolean;
}

export const DEFAULT_CONFIG: LocoClientConfig = {
  host: "211.249.240.122",
  port: 9282,
  useTLS: false,
  serverPublicKey: "",
};

export interface LoginCredentials {
  /** OAuth token obtained from KakaoTalk auth */
  oauthToken: string;
  /** Device UUID */
  duuid: string;
  /** User ID */
  userId: number;
  /** App version string */
  appVer: string;
  /** Language code */
  lang: string;
  /** Mobile Country Code + Mobile Network Code */
  mccmnc: string;
}
