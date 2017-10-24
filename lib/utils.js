'use strict';

var scrypt = require('scrypt.js');
var cryptoJS = require('crypto-js');
var EC = require('elliptic').ec;

var Random = require('bitcore-lib').crypto.Random;

var ec = new EC('secp256k1');

function isHexStringValid(hex, length) {
  var requiredLengthWithPrefix = length + '0x'.length;

  if (hex.length !== requiredLengthWithPrefix) {
    return false;
  }

  var hexRe = new RegExp('^(0x)([A-F\\d]{' + length + '})$', 'i');

  return hexRe.test(hex);
}

function getAddressFromPublicKey(publicKey) {
  var keyPair = ec.keyFromPublic(publicKey, 'hex');

  return getAddressFromKeyPair(keyPair);
}

function getAddressFromPrivateKey(privateKey) {
  var privateKeyWithoutHexPrefix = privateKey.replace(/^0x/i, '');

  var keyPair = ec.genKeyPair();
  keyPair._importPrivate(privateKeyWithoutHexPrefix, 'hex');

  return getAddressFromKeyPair(keyPair);
}

function getAddressFromKeyPair(keyPair) {
  var compact = false;

  var publicKey = keyPair.getPublic(compact, 'hex').slice(2);
  var publicKeyWordArray = cryptoJS.enc.Hex.parse(publicKey);
  var hash = cryptoJS.SHA3(publicKeyWordArray, { outputLength: 256 });
  var address = hash.toString(cryptoJS.enc.Hex).slice(24);

  return add0x(address);
}

function deriveKeyFromPassword(password, scryptParams, derivedKeyLength, salt) {
  var N = scryptParams.N,
      r = scryptParams.r,
      p = scryptParams.p;

  var derivedKey = scrypt(password, salt, N, r, p, derivedKeyLength);

  return new Uint8Array(derivedKey);
}

function leftPadString(stringToPad, padChar, totalLength) {
  var leftPadLength = totalLength - stringToPad.length;
  var leftPad = '';

  for (var i = 0; i < leftPadLength; i += 1) {
    leftPad += padChar;
  }

  return '' + leftPad + stringToPad;
}

function generateSalt(byteCount) {
  return Random.getRandomBuffer(byteCount).toString('base64');
}

function add0x(data) {
  if (data.indexOf('0x') === 0) {
    return data;
  }

  return '0x' + data;
}

module.exports = {
  isHexStringValid: isHexStringValid,
  getAddressFromPublicKey: getAddressFromPublicKey,
  getAddressFromPrivateKey: getAddressFromPrivateKey,
  deriveKeyFromPassword: deriveKeyFromPassword,
  leftPadString: leftPadString,
  generateSalt: generateSalt,
  add0x: add0x
};