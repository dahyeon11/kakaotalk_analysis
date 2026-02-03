/**
 * LOCO Checkin — connects to the checkin server (e.g. ticket-loco.kakao.com:5242)
 * over TLS with plaintext LOCO (same as booking), sends CHECKIN, and returns
 * the LOCO session server host:port for the encrypted connection.
 */

import { LocoSocket } from "./socket.ts";
import type { LocoClientConfig, LoginCredentials } from "../types/index.ts";

export interface CheckinRequest {
  userId: number;
  os: string;
  ntype: number;
  appVer: string;
  lang: string;
  MCCMNC: string;
}

export interface CheckinResponse {
  /** LOCO session server host */
  host: string;
  /** LOCO session server port */
  port: number;
  /** Full raw response for debugging */
  raw: Record<string, unknown>;
}

/**
 * Connect to the checkin server via TLS + plaintext LOCO,
 * send CHECKIN, and return the LOCO session server address.
 */
export async function fetchCheckinServer(
  checkinHost: string,
  checkinPort: number,
  serverPublicKey: string,
  req: CheckinRequest,
): Promise<CheckinResponse> {
  const config: LocoClientConfig = {
    host: checkinHost,
    port: checkinPort,
    useTLS: true,
    serverPublicKey,
  };

  const socket = new LocoSocket(config, { plaintext: true });

  try {
    await socket.connect();
    console.log(`[Checkin] Connected to ${checkinHost}:${checkinPort}`);

    const resp = await socket.request("CHECKIN", {
      userId: req.userId,
      os: req.os,
      ntype: req.ntype,
      appVer: req.appVer,
      lang: req.lang,
      MCCMNC: req.MCCMNC,
    });

    console.log("[Checkin] CHECKIN response received");

    const body = resp.body;
    const host = (body["host"] as string) ?? "";
    const port = (body["port"] as number) ?? 0;

    return { host, port, raw: body };
  } finally {
    socket.disconnect();
  }
}
