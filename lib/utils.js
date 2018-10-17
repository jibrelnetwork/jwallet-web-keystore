'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.add0x = add0x;
exports.getChecksum = getChecksum;
exports.checkChecksumAddressValid = checkChecksumAddressValid;
exports.checkAddressValid = checkAddressValid;
exports.checkPrivateKeyValid = checkPrivateKeyValid;
exports.getAddressFromPublicKey = getAddressFromPublicKey;
exports.getAddressFromPrivateKey = getAddressFromPrivateKey;
exports.deriveKeyFromPassword = deriveKeyFromPassword;
exports.leftPadString = leftPadString;
exports.generateSalt = generateSalt;

var _scrypt = require('scrypt.js');

var _scrypt2 = _interopRequireDefault(_scrypt);

var _cryptoJs = require('crypto-js');

var _cryptoJs2 = _interopRequireDefault(_cryptoJs);

var _bitcoreLib = require('bitcore-lib');

var _elliptic = require('elliptic');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/* eslint-enable no-use-before-define */

/* eslint-disable no-use-before-define */
var RE_HEX_PREFIX = /^0x/i;
var ENCODER = _cryptoJs2.default.enc.Hex;

var ec = new _elliptic.ec('secp256k1');

function strip0x(data) {
  return data.replace(RE_HEX_PREFIX, '');
}

function add0x(data) {
  if (RE_HEX_PREFIX.test(data)) {
    return data;
  }

  return '0x' + data;
}

function getChecksum(address) {
  var addressLowerCase = strip0x(address).toLowerCase();
  var hash = _cryptoJs2.default.SHA3(addressLowerCase, { outputLength: 256 }).toString(ENCODER);

  var checksum = addressLowerCase.split('').map(function (symbol, index) {
    return parseInt(hash[index], 16) >= 8 ? symbol.toUpperCase() : symbol;
  }).join('');

  return add0x(checksum);
}

function checkNormalizedAddress(address) {
  var isAddressLowerCase = /^0x[0-9a-f]{40}$/.test(address);
  var isAddressUpperCase = /^0x[0-9A-F]{40}$/.test(address);

  return isAddressLowerCase || isAddressUpperCase;
}

function checkChecksumAddressValid(address) {
  return (/^0x[0-9a-fA-F]{40}$/i.test(address) && getChecksum(address) === address
  );
}

function checkAddressValid(address) {
  return checkNormalizedAddress(address) || checkChecksumAddressValid(address);
}

function checkPrivateKeyValid(privateKey) {
  return (/^0x[0-9a-fA-F]{64}$/i.test(privateKey)
  );
}

function getAddressFromKeyPair(keyPair) {
  var isCompact = false;
  var publicKey = keyPair.getPublic(isCompact, 'hex').slice(2);
  var publicKeyWordArray = ENCODER.parse(publicKey);
  var hash = _cryptoJs2.default.SHA3(publicKeyWordArray, { outputLength: 256 });
  var address = hash.toString(ENCODER).slice(24);

  return getChecksum(address);
}

function getAddressFromPublicKey(publicKey) {
  var keyPair = ec.keyFromPublic(publicKey, 'hex');

  return getAddressFromKeyPair(keyPair);
}

function getAddressFromPrivateKey(privateKey) {
  var keyPair = ec.genKeyPair();
  keyPair._importPrivate(strip0x(privateKey), 'hex');

  return getAddressFromKeyPair(keyPair);
}

function deriveKeyFromPassword(password, scryptParams, derivedKeyLength, salt) {
  var N = scryptParams.N,
      r = scryptParams.r,
      p = scryptParams.p;

  var derivedKey = (0, _scrypt2.default)(password, salt, N, r, p, derivedKeyLength);

  return new Uint8Array(derivedKey);
}

function leftPadString(stringToPad, padChar, totalLength) {
  var leftPad = padChar.repeat(totalLength - stringToPad.length);

  return '' + leftPad + stringToPad;
}

function generateSalt(byteCount) {
  return _bitcoreLib.crypto.Random.getRandomBuffer(byteCount).toString('base64');
}