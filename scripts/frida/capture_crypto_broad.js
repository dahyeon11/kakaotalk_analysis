/**
 * Frida script to capture crypto operations - broader hooks
 * Hooks multiple Cipher overloads and also socket writes
 *
 * Usage: frida -U -n com.kakao.talk -l capture_crypto_broad.js
 */

Java.perform(function () {
  console.log("[*] Starting broad crypto capture...");

  var Cipher = Java.use("javax.crypto.Cipher");

  // Hook ALL Cipher.init overloads
  var initOverloads = Cipher.init.overloads;
  console.log("[*] Found " + initOverloads.length + " Cipher.init overloads");

  initOverloads.forEach(function (overload, idx) {
    overload.implementation = function () {
      var algo = this.getAlgorithm();
      console.log("\n=== Cipher.init[" + idx + "] ===");
      console.log("Algorithm: " + algo);
      console.log("Mode: " + (arguments[0] === 1 ? "ENCRYPT" : (arguments[0] === 2 ? "DECRYPT" : arguments[0])));

      for (var i = 1; i < arguments.length; i++) {
        var arg = arguments[i];
        if (arg && arg.getEncoded) {
          console.log("Key (" + arg.getEncoded().length + " bytes): " + bytesToHex(arg.getEncoded()));
        } else if (arg && arg.getIV) {
          console.log("IV (" + arg.getIV().length + " bytes): " + bytesToHex(arg.getIV()));
        } else if (arg) {
          console.log("Arg[" + i + "]: " + arg.toString());
        }
      }
      return overload.apply(this, arguments);
    };
  });

  // Hook ALL Cipher.doFinal overloads
  var doFinalOverloads = Cipher.doFinal.overloads;
  console.log("[*] Found " + doFinalOverloads.length + " Cipher.doFinal overloads");

  doFinalOverloads.forEach(function (overload, idx) {
    overload.implementation = function () {
      var algo = this.getAlgorithm();
      var result = overload.apply(this, arguments);

      console.log("\n=== Cipher.doFinal[" + idx + "] (" + algo + ") ===");

      // Try to get input bytes
      if (arguments.length > 0 && arguments[0]) {
        var input = arguments[0];
        if (input.length !== undefined) {
          var len = arguments.length > 2 ? arguments[2] : input.length;
          var off = arguments.length > 1 && typeof arguments[1] === 'number' ? arguments[1] : 0;
          console.log("Input (" + len + " bytes): " + bytesToHex(input).substring(off*2, (off+Math.min(len,100))*2) + (len > 100 ? "..." : ""));
        }
      }

      if (result && result.length !== undefined) {
        console.log("Output (" + result.length + " bytes): " + bytesToHex(result).substring(0, 200) + (result.length > 100 ? "..." : ""));
      }

      return result;
    };
  });

  // Hook Cipher.update as well
  var updateOverloads = Cipher.update.overloads;
  console.log("[*] Found " + updateOverloads.length + " Cipher.update overloads");

  updateOverloads.forEach(function (overload, idx) {
    overload.implementation = function () {
      var algo = this.getAlgorithm();
      var result = overload.apply(this, arguments);

      if (algo && (algo.indexOf("AES") !== -1 || algo.indexOf("RSA") !== -1)) {
        console.log("\n=== Cipher.update[" + idx + "] (" + algo + ") ===");
        if (arguments[0] && arguments[0].length !== undefined) {
          console.log("Input (" + arguments[0].length + " bytes)");
        }
        if (result && result.length !== undefined) {
          console.log("Output (" + result.length + " bytes)");
        }
      }
      return result;
    };
  });

  // Also hook SecretKeySpec constructor to see key creation
  var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
  SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (keyBytes, algo) {
    console.log("\n=== SecretKeySpec ===");
    console.log("Algorithm: " + algo);
    console.log("Key (" + keyBytes.length + " bytes): " + bytesToHex(keyBytes));
    return this.$init(keyBytes, algo);
  };

  // Hook IvParameterSpec
  var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
  IvParameterSpec.$init.overload("[B").implementation = function (iv) {
    console.log("\n=== IvParameterSpec ===");
    console.log("IV (" + iv.length + " bytes): " + bytesToHex(iv));
    return this.$init(iv);
  };

  function bytesToHex(bytes) {
    var hex = "";
    for (var i = 0; i < bytes.length; i++) {
      hex += ("0" + ((bytes[i] & 0xff).toString(16))).slice(-2);
    }
    return hex;
  }

  console.log("[*] All hooks installed. Trigger app reconnection.");
});
