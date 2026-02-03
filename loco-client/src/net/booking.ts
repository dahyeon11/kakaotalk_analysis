/**
 * LOCO Booking — connects to booking-loco.kakao.com:443 over TLS,
 * performs LOCO RSA handshake, sends GETCONF, and returns checkin server info.
 *
 * Flow (based on kiwitalk reference):
 *   1. TLS connect to booking-loco.kakao.com:443
 *   2. LOCO RSA handshake (encrypt AES session key)
 *   3. Send GETCONF command → receive checkin server list
 *   4. Disconnect
 */

import { LocoSocket } from "./socket.ts";
import type { LocoClientConfig } from "../types/index.ts";

export interface GetConfRequest {
  os: string;
  MCCMNC: string;
  model: string;
}

export interface GetConfResponse {
  /** Checkin host list (v2sl) */
  checkinHosts: string[];
  /** Checkin host list (lsl - preferred) */
  checkinHostsLsl: string[];
  /** Available ports */
  ports: number[];
  /** Full raw response for debugging */
  raw: Record<string, unknown>;
}

const BOOKING_HOST = "booking-loco.kakao.com";
const BOOKING_PORT = 443;

/**
 * Connect to the booking server via TLS + LOCO protocol,
 * send GETCONF, and return checkin server information.
 */
export async function fetchBookingServer(
  serverPublicKey: string,
  req: GetConfRequest,
): Promise<GetConfResponse> {
  const config: LocoClientConfig = {
    host: BOOKING_HOST,
    port: BOOKING_PORT,
    useTLS: true,
    serverPublicKey,
  };

  const socket = new LocoSocket(config, { plaintext: true });

  try {
    await socket.connect();
    console.log("[Booking] Connected to booking-loco.kakao.com:443");

    const resp = await socket.request("GETCONF", {
      MCCMNC: req.MCCMNC,
      os: req.os,
      model: req.model,
    });

    console.log("[Booking] GETCONF response received");

    const body = resp.body;

    // Extract checkin hosts from ticket.lsl or ticket.v2sl
    const ticket = (body["ticket"] as Record<string, unknown>) ?? {};
    const lsl = (ticket["lsl"] as string[]) ?? [];
    const v2sl = (ticket["v2sl"] as string[]) ?? [];

    // Extract ports from wifi config
    const wifi = (body["wifi"] as Record<string, unknown>) ?? {};
    const ports = (wifi["ports"] as number[]) ?? [9282];

    return {
      checkinHosts: v2sl,
      checkinHostsLsl: lsl,
      ports,
      raw: body,
    };
  } finally {
    socket.disconnect();
  }
}

/**
 * Convenience function: booking → pick first checkin host + port.
 * Returns { host, port } ready for checkin connection.
 */
export async function resolveCheckinServer(
  serverPublicKey: string,
  req: GetConfRequest,
  fallbackHost = "121.53.93.55",
  fallbackPort = 9282,
): Promise<{ host: string; port: number }> {
  try {
    const conf = await fetchBookingServer(serverPublicKey, req);
    const hosts = conf.checkinHostsLsl.length > 0
      ? conf.checkinHostsLsl
      : conf.checkinHosts;
    const host = hosts[0] ?? fallbackHost;
    const port = conf.ports[0] ?? fallbackPort;
    return { host, port };
  } catch (err) {
    console.warn("[Booking] Failed:", (err as Error).message, "— using fallback");
    return { host: fallbackHost, port: fallbackPort };
  }
}
