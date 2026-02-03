/**
 * parse_loco_dump.js — Frida script that hooks LOCO Cipher.doFinal,
 * decodes plaintext LOCO packets as BSON, and prints structured output.
 *
 * Usage:
 *   frida -U -f com.kakao.talk -l parse_loco_dump.js
 *   frida -U -n com.kakao.talk -l parse_loco_dump.js
 */

"use strict";

const LOCO_FILES = [
  "V2SLSink.kt",     // encrypt (client → server)
  "V2SLSource.kt",   // decrypt (server → client)
];

function hexDump(bytes, maxLen) {
  const len = Math.min(bytes.length, maxLen || 256);
  const parts = [];
  for (let i = 0; i < len; i++) {
    parts.push(("0" + (bytes[i] & 0xff).toString(16)).slice(-2));
  }
  return parts.join(" ");
}

function readInt32LE(buf, off) {
  return (buf[off] | (buf[off+1] << 8) | (buf[off+2] << 16) | (buf[off+3] << 24)) >>> 0;
}

function readInt64LE(buf, off) {
  const lo = readInt32LE(buf, off);
  const hi = readInt32LE(buf, off + 4);
  // Return as Number (safe for values < 2^53)
  return hi * 0x100000000 + lo;
}

function readCString(buf, off) {
  let end = off;
  while (end < buf.length && buf[end] !== 0) end++;
  const bytes = buf.slice(off, end);
  try {
    // Try UTF-8 decode
    const arr = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) arr[i] = bytes[i] & 0xff;
    // Use Java for UTF-8 decoding
    return Java.use("java.lang.String").$new(arr, "UTF-8");
  } catch (e) {
    return String.fromCharCode.apply(null, bytes.map(function(b) { return b & 0xff; }));
  }
}

/**
 * Minimal BSON parser — enough for LOCO packet bodies.
 * Supports: double(1), string(2), document(3), array(4), binary(5),
 *           boolean(8), int32(16/0x10), int64(18/0x12)
 */
function parseBSON(buf, offset) {
  offset = offset || 0;
  const totalSize = readInt32LE(buf, offset);
  const doc = {};
  let pos = offset + 4;
  const end = offset + totalSize;

  while (pos < end) {
    const type = buf[pos] & 0xff;
    pos++;
    if (type === 0) break; // terminator

    // Read field name (cstring)
    let nameEnd = pos;
    while (nameEnd < end && buf[nameEnd] !== 0) nameEnd++;
    const name = readCString(buf, pos);
    pos = nameEnd + 1;

    switch (type) {
      case 0x01: { // double
        // Read 8 bytes as IEEE 754 double
        const bytes = [];
        for (let i = 0; i < 8; i++) bytes.push(buf[pos + i] & 0xff);
        // Little-endian double
        const ab = new ArrayBuffer(8);
        const view = new DataView(ab);
        for (let i = 0; i < 8; i++) view.setUint8(i, bytes[i]);
        doc[name] = view.getFloat64(0, true);
        pos += 8;
        break;
      }
      case 0x02: { // string
        const strLen = readInt32LE(buf, pos);
        pos += 4;
        doc[name] = readCString(buf, pos);
        pos += strLen;
        break;
      }
      case 0x03: { // embedded document
        const subSize = readInt32LE(buf, pos);
        doc[name] = parseBSON(buf, pos);
        pos += subSize;
        break;
      }
      case 0x04: { // array
        const arrSize = readInt32LE(buf, pos);
        const arrDoc = parseBSON(buf, pos);
        // Convert object with "0", "1", ... keys to array
        const arr = [];
        for (let i = 0; ; i++) {
          if (arrDoc.hasOwnProperty(String(i))) {
            arr.push(arrDoc[String(i)]);
          } else {
            break;
          }
        }
        doc[name] = arr;
        pos += arrSize;
        break;
      }
      case 0x05: { // binary
        const binLen = readInt32LE(buf, pos);
        pos += 4;
        const subtype = buf[pos] & 0xff;
        pos++;
        const binData = [];
        for (let i = 0; i < binLen; i++) binData.push(buf[pos + i] & 0xff);
        doc[name] = "<binary:" + binLen + "b,subtype=" + subtype + "> " + hexDump(binData, 32);
        pos += binLen;
        break;
      }
      case 0x08: { // boolean
        doc[name] = buf[pos] !== 0;
        pos++;
        break;
      }
      case 0x0A: { // null
        doc[name] = null;
        break;
      }
      case 0x10: { // int32
        doc[name] = readInt32LE(buf, pos) | 0; // signed
        pos += 4;
        break;
      }
      case 0x12: { // int64
        doc[name] = readInt64LE(buf, pos);
        pos += 8;
        break;
      }
      default: {
        doc[name] = "<unknown_bson_type_0x" + type.toString(16) + ">";
        // Can't continue safely — unknown length
        return doc;
      }
    }
  }
  return doc;
}

/**
 * Parse a plaintext LOCO packet buffer.
 *
 * Layout (22-byte header):
 *   [0..3]   packetId    (uint32 LE)
 *   [4..5]   statusCode  (uint16 LE)
 *   [6..16]  command     (11 bytes, null-padded ASCII)
 *   [17]     bodyType    (uint8, 0 = BSON)
 *   [18..21] bodyLength  (uint32 LE)
 *   [22..]   body        (BSON)
 */
function parseLocoPacket(buf) {
  if (buf.length < 22) return null;

  const packetId = readInt32LE(buf, 0);
  const statusCode = (buf[4] & 0xff) | ((buf[5] & 0xff) << 8);

  // Command: 11 bytes at offset 6
  let cmd = "";
  for (let i = 6; i < 17; i++) {
    const ch = buf[i] & 0xff;
    if (ch === 0) break;
    cmd += String.fromCharCode(ch);
  }

  const bodyType = buf[17] & 0xff;
  const bodyLength = readInt32LE(buf, 18);

  let body = null;
  if (bodyType === 0 && bodyLength > 0 && buf.length >= 22 + bodyLength) {
    try {
      body = parseBSON(buf, 22);
    } catch (e) {
      body = { _parseError: e.toString() };
    }
  }

  return {
    packetId: packetId,
    statusCode: statusCode,
    command: cmd,
    bodyType: bodyType,
    bodyLength: bodyLength,
    body: body,
  };
}

function getCaller() {
  const trace = Java.use("java.lang.Thread").currentThread().getStackTrace();
  for (let i = 0; i < trace.length; i++) {
    const fn = trace[i].getFileName();
    if (fn && LOCO_FILES.indexOf(fn) !== -1) {
      return fn;
    }
  }
  return null;
}

function formatBody(body, indent) {
  indent = indent || "  ";
  if (!body) return indent + "(empty)";
  const lines = [];
  const keys = Object.keys(body);
  for (let i = 0; i < keys.length; i++) {
    const k = keys[i];
    const v = body[k];
    if (v && typeof v === "object" && !Array.isArray(v)) {
      lines.push(indent + k + ":");
      lines.push(formatBody(v, indent + "  "));
    } else if (Array.isArray(v)) {
      if (v.length === 0) {
        lines.push(indent + k + ": []");
      } else if (typeof v[0] === "object") {
        lines.push(indent + k + ": [");
        for (let j = 0; j < v.length; j++) {
          lines.push(indent + "  [" + j + "]:");
          lines.push(formatBody(v[j], indent + "    "));
        }
        lines.push(indent + "]");
      } else {
        lines.push(indent + k + ": [" + v.join(", ") + "]");
      }
    } else if (typeof v === "string" && v.length > 80) {
      lines.push(indent + k + ': "' + v.substring(0, 77) + '..."');
    } else if (typeof v === "string") {
      lines.push(indent + k + ': "' + v + '"');
    } else {
      lines.push(indent + k + ": " + v);
    }
  }
  return lines.join("\n");
}

// ---- Hook ----

setTimeout(function() {
  Java.perform(function() {
    var Cipher = Java.use("javax.crypto.Cipher");
    var counter = 0;

    // Hook doFinal(byte[]) — this is what LOCO uses
    Cipher.doFinal.overload("[B").implementation = function(input) {
      var caller = getCaller();
      if (!caller) return this.doFinal(input);

      var algo = this.getAlgorithm();
      if (algo.indexOf("AES") === -1) return this.doFinal(input);

      var mode = this.getOpMode ? this.getOpMode() : -1;
      var isEncrypt = (mode === 1); // Cipher.ENCRYPT_MODE
      var direction = isEncrypt ? "→ SEND" : "← RECV";

      // For encrypt: input is plaintext. For decrypt: we need result.
      var result = this.doFinal(input);

      var plainBuf;
      if (isEncrypt) {
        plainBuf = input;
      } else {
        plainBuf = result;
      }

      // Convert to JS array
      var bytes = [];
      for (var i = 0; i < plainBuf.length; i++) {
        bytes.push(plainBuf[i]);
      }

      var parsed = parseLocoPacket(bytes);
      if (parsed) {
        counter++;
        console.log("\n═══════════════════════════════════════════════════");
        console.log("[" + counter + "] " + direction + "  " + parsed.command + "  (id=" + parsed.packetId + ", status=" + parsed.statusCode + ", bodyLen=" + parsed.bodyLength + ")");
        console.log("───────────────────────────────────────────────────");
        if (parsed.body) {
          console.log(formatBody(parsed.body));
        }
        console.log("═══════════════════════════════════════════════════");
      }

      return result;
    };

    console.log("[parse_loco_dump] Hooks installed. Waiting for LOCO packets...");
  });
}, 3000);
