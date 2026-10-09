var cbc = require('@noble/ciphers/aes.js').cbc;
var hmac = require('@noble/hashes/hmac.js').hmac;
var sha256 = require('@noble/hashes/sha2.js').sha256;

var BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

// Makes a Base64 string a url-safe base64 string
var urlsafe = function urlsafe(string) {
  return string.replace(/\+/g, '-').replace(/\//g, '_') //.replace(/=+$/, '')
}

// parse a Hex string to an Int
var parseHex = function parseHex(hexString) {
  return parseInt('0x' + hexString);
}

// turn bits into number of chars in a hex string
var hexBits = function hexBits(bits) {
  return bits / 8 * 2;
}

// convert a byte array to a hex string
var bytesToHex = function bytesToHex(bytes) {
  var hex = '';
  for (var i = 0; i < bytes.length; i++) {
    hex += (bytes[i] & 0xff).toString(16).padStart(2, '0');
  }
  return hex;
}

// convert a hex string to a Uint8Array
var hexToBytes = function hexToBytes(hex) {
  var bytes = new Uint8Array(Math.floor(hex.length / 2));
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

// convert bytes to standard base64, with padding
var bytesToBase64 = function bytesToBase64(bytes) {
  var out = '';
  for (var i = 0; i < bytes.length; i += 3) {
    var n = (bytes[i] << 16) | ((bytes[i + 1] || 0) << 8) | (bytes[i + 2] || 0);
    out += BASE64[(n >> 18) & 63] + BASE64[(n >> 12) & 63];
    out += i + 1 < bytes.length ? BASE64[(n >> 6) & 63] : '=';
    out += i + 2 < bytes.length ? BASE64[n & 63] : '=';
  }
  return out;
}

// convert standard or url-safe base64 to bytes, skipping anything outside
// the alphabet the way Node's Buffer.from(string, 'base64') does
var base64ToBytes = function base64ToBytes(string) {
  var bytes = [];
  var bits = 0;
  var value = 0;
  for (var i = 0; i < string.length; i++) {
    var c = string[i];
    var v = c === '-' ? 62 : c === '_' ? 63 : BASE64.indexOf(c);
    if (c === '=') break;
    if (v < 0) continue;
    value = (value << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >> bits) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}

// convert base64 string to hex string
var decode64toHex = function decode64(string) {
  return bytesToHex(base64ToBytes(string));
}

// convert array to hex string
var ArrayToHex = function ArrayToHex(array) {
  return bytesToHex(array);
}

var randomHex = function (size) {
  return bytesToHex(globalThis.crypto.getRandomValues(new Uint8Array(size)));
}

var setIV = function setIV(iv_array) {
  if (iv_array) {
    this.ivHex = ArrayToHex(iv_array);
  } else {
    this.ivHex = randomHex(128 / 8);
  }
  this.iv = hexToBytes(this.ivHex);
  return this.ivHex;
}

//convert Time object or now into bytes
var timeBytes = function timeBytes(time) {
  if (time) {
    time = Math.floor(time / 1000)
  } else {
    time = (Math.round(new Date() / 1000))
  }
  var hexTime = time.toString(16).padStart(16, '0')
  return hexToBytes(hexTime);
}

var concatBytes = function concatBytes() {
  var length = 0;
  for (var i = 0; i < arguments.length; i++) length += arguments[i].length;
  var out = new Uint8Array(length);
  var offset = 0;
  for (var j = 0; j < arguments.length; j++) {
    out.set(arguments[j], offset);
    offset += arguments[j].length;
  }
  return out;
}

var fernet = function fernet(opts) {
  this.parseHex = parseHex;
  this.decode64toHex = decode64toHex;
  this.hexBits = hexBits;
  this.urlsafe = urlsafe;
  this.bytesToHex = bytesToHex;
  this.hexToBytes = hexToBytes;
  this.bytesToBase64 = bytesToBase64;
  this.base64ToBytes = base64ToBytes;

  //Sets the secret from base64 encoded value
  this.setSecret = function setSecret(secret64) {
    this.secret = new this.Secret(secret64);
    return this.secret;
  }

  this.ArrayToHex = ArrayToHex;
  this.setIV = setIV;

  this.encryptMessage = function (message, encryptionKey, iv) {
    return cbc(encryptionKey, iv).encrypt(new TextEncoder().encode(message));
  }

  this.decryptMessage = function (cipherText, encryptionKey, iv) {
    var decrypted = cbc(encryptionKey, iv).decrypt(cipherText);
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(decrypted);
    } catch (e) {
      throw new Error('Malformed UTF-8 data');
    }
  }

  this.timeBytes = timeBytes;

  this.createToken = function (signingKey, time, iv, cipherText) {
    var hmac = this.createHmac(signingKey, time, iv, cipherText);
    var tokenBytes = concatBytes(hexToBytes(this.versionHex), time, iv, cipherText, hmac);
    return urlsafe(bytesToBase64(tokenBytes));
  }

  this.createHmac = function createHmac(signingKey, time, iv, cipherText) {
    var hmacBytes = concatBytes(hexToBytes(this.versionHex), time, iv, cipherText);
    return hmac(sha256, signingKey, hmacBytes);
  }

  this.Secret = require('./lib/secret');
  this.Token = require('./lib/token')(this);

  opts = opts || {};
  this.ttl = opts.ttl || 60;
  // because (0 || x) always equals x
  if (opts.ttl === 0) this.ttl = 0;
  this.versionHex = '80';
  this.setIV(opts.iv);
  if (opts.secret) { this.setSecret(opts.secret) }
}

exports = module.exports = fernet;
fernet.call(exports)
