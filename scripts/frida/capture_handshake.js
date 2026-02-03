/**
 * Frida script to capture raw bytes written to LOCO server sockets.
 * Shows the exact handshake + first encrypted packet for comparison.
 *
 * Usage: frida -U -n com.kakao.talk -l capture_handshake.js
 */

Java.perform(function () {
  var SocketOutputStream = Java.use("java.net.SocketOutputStream");
  var Socket = Java.use("java.net.Socket");

  // Track sockets by their output stream hash
  var captured = {};

  SocketOutputStream.write.overload("[B", "int", "int").implementation = function (b, off, len) {
    var socket = this.socket.value;
    if (socket) {
      try {
        var port = socket.getPort();
        // LOCO ports: 9282, 5228, 5242, 10009, 995, 8080, 5223
        var locoPorts = [9282, 5228, 5242, 10009, 995, 8080, 5223];
        if (locoPorts.indexOf(port) !== -1) {
          var host = socket.getInetAddress().getHostAddress();
          var key = host + ":" + port;
          if (!captured[key]) {
            captured[key] = { writeCount: 0 };
          }
          var info = captured[key];
          info.writeCount++;

          var bytes = Java.array("byte", b);
          var data = [];
          for (var i = off; i < off + Math.min(len, 300); i++) {
            data.push(("0" + ((bytes[i] & 0xff).toString(16))).slice(-2));
          }

          console.log("\n=== SOCKET WRITE #" + info.writeCount + " to " + key + " ===");
          console.log("Length: " + len + " bytes");
          console.log("Hex: " + data.join(""));

          if (info.writeCount === 1 && len >= 12) {
            // Parse as handshake
            var keyLen = (bytes[off] & 0xff) | ((bytes[off+1] & 0xff) << 8) |
                         ((bytes[off+2] & 0xff) << 16) | ((bytes[off+3] & 0xff) << 24);
            var encType = (bytes[off+4] & 0xff) | ((bytes[off+5] & 0xff) << 8) |
                          ((bytes[off+6] & 0xff) << 16) | ((bytes[off+7] & 0xff) << 24);
            var blockMode = (bytes[off+8] & 0xff) | ((bytes[off+9] & 0xff) << 8) |
                            ((bytes[off+10] & 0xff) << 16) | ((bytes[off+11] & 0xff) << 24);
            console.log("Parsed handshake: keyLen=" + keyLen + " encType=" + encType + " blockMode=" + blockMode);
            console.log("Total packet: " + len + " bytes (expected: 12 + keyLen = " + (12 + keyLen) + ")");
          }

          if (info.writeCount === 2 && len >= 4) {
            // Parse as encrypted packet
            var pktLen = (bytes[off] & 0xff) | ((bytes[off+1] & 0xff) << 8) |
                         ((bytes[off+2] & 0xff) << 16) | ((bytes[off+3] & 0xff) << 24);
            console.log("Encrypted packet: length field=" + pktLen + " total=" + len);
          }
        }
      } catch (e) {
        // ignore
      }
    }
    return this.write(b, off, len);
  };

  console.log("[*] Hooking SocketOutputStream.write for LOCO ports...");
  console.log("[*] Open a chat or trigger a reconnect to capture handshake.");
});
