/**
 * LOCO Booking API — fetches the LOCO server host:port before connecting.
 *
 * KakaoTalk calls `https://booking-loco.kakao.com/booking` with a JSON body
 * to discover which LOCO server to connect to. The response contains host/port
 * for the raw TCP LOCO connection.
 */

export interface BookingRequest {
  /** OS type: "android" or "ios" */
  os: string;
  /** App version */
  appVer: string;
  /** MCCMNC */
  MCCMNC: string;
  /** Country ISO */
  countryISO?: string;
  /** Language */
  lang?: string;
}

export interface BookingResponse {
  /** LOCO server host */
  host: string;
  /** LOCO server port */
  port: number;
  /** IPv6 host (if available) */
  host6?: string;
  /** Fallback hosts */
  cshost?: string;
  /** Fallback port */
  csport?: number;
}

const BOOKING_URL = "https://booking-loco.kakao.com/booking";

/**
 * Call the booking API to get the LOCO server address.
 * Falls back to the provided default host:port on failure.
 */
export async function fetchBookingServer(
  req: BookingRequest,
  fallbackHost = "211.249.240.122",
  fallbackPort = 9282,
): Promise<BookingResponse> {
  try {
    const body = JSON.stringify({
      os: req.os,
      appVer: req.appVer,
      MCCMNC: req.MCCMNC,
      countryISO: req.countryISO ?? "KR",
      lang: req.lang ?? "ko",
    });

    const resp = await fetch(BOOKING_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": `KT/${req.appVer} An/14.0 ko`,
        "A": "android/" + req.appVer + "/ko",
      },
      body,
    });

    if (!resp.ok) {
      console.warn(`[Booking] HTTP ${resp.status}, using fallback`);
      return { host: fallbackHost, port: fallbackPort };
    }

    const data = (await resp.json()) as Record<string, unknown>;

    // The booking response may have the server info at top level or nested
    const host = (data["host"] as string) ?? fallbackHost;
    const port = (data["port"] as number) ?? fallbackPort;

    return {
      host,
      port,
      host6: data["host6"] as string | undefined,
      cshost: data["cshost"] as string | undefined,
      csport: data["csport"] as number | undefined,
    };
  } catch (err) {
    console.warn("[Booking] Failed:", (err as Error).message, "— using fallback");
    return { host: fallbackHost, port: fallbackPort };
  }
}
