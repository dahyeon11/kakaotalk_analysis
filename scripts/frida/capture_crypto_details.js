/**
 * Frida script to capture detailed LOCO encryption info:
 * - AES key used
 * - Plaintext LOCO packet before encryption
 * - IV used
 * - Ciphertext output
 *
 * Usage: frida -U -n com.kakao.talk -l capture_crypto_details.js
 */

Java.perform(function () {
  console.log("[*] Hooking Cipher for AES-256-CFB details...");

  var Cipher = Java.use("javax.crypto.Cipher");
  var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
  var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");

  // Track cipher instances
  var cipherInfo = {};

  // Hook Cipher.init to capture key and IV
  Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function (opmode, key, params) {
    var algo = this.getAlgorithm();
    if (algo && algo.indexOf("AES") !== -1 && algo.indexOf("CFB") !== -1) {
      var keyBytes = key.getEncoded();
      var keyHex = bytesToHex(keyBytes);

      var ivHex = "";
      if (params && params.$className.indexOf("IvParameterSpec") !== -1) {
        var ivSpec = Java.cast(params, IvParameterSpec);
        var ivBytes = ivSpec.getIV();
        ivHex = bytesToHex(ivBytes);
      }

      var mode = opmode === 1 ? "ENCRYPT" : "DECRYPT";
      console.log("\n=== AES-CFB " + mode + " init ===");
      console.log("Algorithm: " + algo);
      console.log("Key (" + keyBytes.length + " bytes): " + keyHex);
      console.log("IV (" + (ivHex.length/2) + " bytes): " + ivHex);

      // Store for later correlation
      cipherInfo[this.hashCode()] = {
        mode: mode,
        key: keyHex,
        iv: ivHex
      };
    }
    return this.init(opmode, key, params);
  };

  // Hook Cipher.doFinal to capture plaintext/ciphertext
  Cipher.doFinal.overload("[B").implementation = function (input) {
    var result = this.doFinal(input);
    var algo = this.getAlgorithm();

    if (algo && algo.indexOf("AES") !== -1 && algo.indexOf("CFB") !== -1) {
      var info = cipherInfo[this.hashCode()] || { mode: "UNKNOWN" };

      console.log("\n=== AES-CFB " + info.mode + " doFinal ===");
      if (info.mode === "ENCRYPT") {
        console.log("Plaintext (" + input.length + " bytes): " + bytesToHex(input).substring(0, 200) + "...");
        console.log("Ciphertext (" + result.length + " bytes): " + bytesToHex(result).substring(0, 200) + "...");

        // Parse LOCO header from plaintext
        if (input.length >= 22) {
          var id = (input[0] & 0xff) | ((input[1] & 0xff) << 8) | ((input[2] & 0xff) << 16) | ((input[3] & 0xff) << 24);
          var status = (input[4] & 0xff) | ((input[5] & 0xff) << 8);
          var cmd = "";
          for (var i = 6; i < 17 && input[i] !== 0; i++) {
            cmd += String.fromCharCode(input[i] & 0xff);
          }
          var bodyType = input[17] & 0xff;
          var bodyLen = (input[18] & 0xff) | ((input[19] & 0xff) << 8) | ((input[20] & 0xff) << 16) | ((input[21] & 0xff) << 24);

          console.log("LOCO Header: id=" + id + " status=" + status + " cmd=" + cmd + " bodyType=" + bodyType + " bodyLen=" + bodyLen);
          console.log("Total LOCO packet: " + input.length + " bytes (header 22 + body " + bodyLen + ")");
        }
      } else {
        console.log("Ciphertext (" + input.length + " bytes)");
        console.log("Plaintext (" + result.length + " bytes): " + bytesToHex(result).substring(0, 200) + "...");
      }
    }
    return result;
  };

  // Also hook RSA encryption to see what's being encrypted
  Cipher.doFinal.overload("[B", "int", "int").implementation = function (input, offset, len) {
    var result = this.doFinal(input, offset, len);
    var algo = this.getAlgorithm();

    if (algo && algo.indexOf("RSA") !== -1) {
      console.log("\n=== RSA " + algo + " ===");
      console.log("Input (" + len + " bytes): " + bytesToHex(Java.array("byte", input).slice(offset, offset + len)));
      console.log("Output (" + result.length + " bytes): " + bytesToHex(result).substring(0, 128) + "...");
    }
    return result;
  };

  function bytesToHex(bytes) {
    var hex = "";
    for (var i = 0; i < bytes.length; i++) {
      hex += ("0" + ((bytes[i] & 0xff).toString(16))).slice(-2);
    }
    return hex;
  }

  console.log("[*] Ready. Trigger a reconnection to capture crypto details.");
});
