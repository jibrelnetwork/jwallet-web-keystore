'use strict';

var scrypt = require('scrypt');
var cryptoJS = require('crypto-js');
var EC = require('elliptic').ec;

var Random = require('bitcore-lib').crypto.Random;

var ec = new EC('secp256k1');

function isHashStringValid(hash, length) {
  var is0x = hash.indexOf('0x') === 0;
  var hashLength = is0x ? hash.length - 2 : hash.length;

  if (hashLength !== length) {
    return false;
  }

  var hashRe = new RegExp('^(0x)?([A-F\\d]{' + length + '})$', 'i');

  return hashRe.test(hash);
}

function getAddressFromPublicKey(publicKey) {
  var publicKeyWordArray = cryptoJS.enc.Hex.parse(publicKey);
  var hash = cryptoJS.SHA3(publicKeyWordArray, { outputLength: 256 });
  var address = hash.toString(cryptoJS.enc.Hex).slice(24);

  return add0x(address);
}

function getAddressFromPrivateKey(privateKey) {
  var keyEncodingType = 'hex';

  var keyPair = ec.genKeyPair();
  keyPair._importPrivate(privateKey, keyEncodingType);

  var compact = false;

  var publicKey = keyPair.getPublic(compact, keyEncodingType).slice(2);

  return getAddressFromPublicKey(publicKey);
}

function deriveKeyFromPassword(password, scryptParams, derivedKeyLength, salt) {
  var derivedKey = scrypt.hashSync(password, scryptParams, derivedKeyLength, salt);

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
  isHashStringValid: isHashStringValid,
  getAddressFromPublicKey: getAddressFromPublicKey,
  getAddressFromPrivateKey: getAddressFromPrivateKey,
  deriveKeyFromPassword: deriveKeyFromPassword,
  leftPadString: leftPadString,
  generateSalt: generateSalt,
  add0x: add0x
};