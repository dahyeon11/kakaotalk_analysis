export { LocoClient, type ChatMessage } from "./client.ts";
export { LocoSocket } from "./net/index.ts";
export {
  buildLocoPacket,
  parseLocoPacket,
  buildEncryptedPacket,
  parseEncryptedPacket,
  buildHandshakePacket,
  PacketReader,
} from "./protocol/index.ts";
export {
  aesEncryptGCM,
  aesDecryptGCM,
  generateAESKey,
  generateNonce,
  rsaEncryptOAEP,
  toPem,
} from "./crypto/index.ts";
export type * from "./types/index.ts";

// ---------------------------------------------------------------------------
// Example: run directly with `node --experimental-strip-types src/index.ts`
// ---------------------------------------------------------------------------

const isMain = process.argv[1]?.endsWith("index.ts");

if (isMain) {
  const { LocoClient } = await import("./client.ts");

  // ⚠ Replace with real values captured via Frida
  const { toPem } = await import("./crypto/rsa.ts");

  const pubkeyHex = process.env["LOCO_SERVER_PUBKEY_HEX"] ?? "";
  const serverPublicKey = pubkeyHex
    ? toPem(Buffer.from(pubkeyHex, "hex").toString("base64"))
    : "";

  const config = {
    host: "loco.kakao.com",
    port: 443,
    useTLS: true,
    serverPublicKey,
  };

  const credentials = {
    oauthToken: process.env["LOCO_OAUTH_TOKEN"] ?? "",
    duuid: process.env["LOCO_DUUID"] ?? "",
    userId: Number(process.env["LOCO_USER_ID"] ?? "0"),
    appVer: process.env["LOCO_APP_VER"] ?? "26.1.2",
    lang: "ko",
    mccmnc: "45005",
  };

  if (!serverPublicKey || !credentials.oauthToken) {
    console.error(
      "Missing environment variables. Required:\n" +
        "  LOCO_SERVER_PUBKEY_HEX  - Server RSA public key (DER hex)\n" +
        "  LOCO_OAUTH_TOKEN        - OAuth token from Frida capture\n" +
        "  LOCO_DUUID              - Device UUID\n" +
        "  LOCO_USER_ID            - KakaoTalk user ID\n" +
        "  LOCO_APP_VER            - App version (default: 26.1.2)\n",
    );
    process.exit(1);
  }

  const client = new LocoClient(config, credentials);

  // Log every raw packet for protocol analysis
  client.onPacket = (header, body) => {
    console.log(
      `[${header.command}] id=${header.id} status=${header.statusCode}`,
    );
    console.log(JSON.stringify(body, null, 2));
    console.log("---");
  };

  // Log decoded messages
  client.onMessage = (msg) => {
    console.log(
      `\n💬 [Chat ${msg.chatId}] sender=${msg.sender}: ${msg.message}\n`,
    );
  };

  try {
    const loginData = await client.login();
    console.log("[LocoClient] Login successful. Chat data received.");
    client.listen();
  } catch (err) {
    console.error("[LocoClient] Failed:", err);
    client.disconnect();
  }
}
