'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.encryptData = encryptData;
exports.decryptData = decryptData;

var _tweetnacl = require('tweetnacl');

var _tweetnacl2 = _interopRequireDefault(_tweetnacl);

var _tweetnaclUtil = require('tweetnacl-util');

var _tweetnaclUtil2 = _interopRequireDefault(_tweetnaclUtil);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function getNonce(nonceLength) {
  return _tweetnacl2.default.randomBytes(nonceLength);
}

function decodePrivateKey(privateKey) {
  var privateKeyBase = Buffer.from(privateKey).toString('base64');

  return _tweetnaclUtil2.default.decodeBase64(privateKeyBase);
}

function encodeEncryptedData(encryptedData, nonce) {
  return {
    nonce: _tweetnaclUtil2.default.encodeBase64(nonce),
    data: _tweetnaclUtil2.default.encodeBase64(encryptedData)
  };
}

function encryptNaclSecretbox(data, derivedKey, isPrivateKey) {
  var nonce = getNonce(_tweetnacl2.default.secretbox.nonceLength);
  var dataToEncrypt = isPrivateKey ? decodePrivateKey(data) : _tweetnaclUtil2.default.decodeUTF8(data);
  var encryptedData = _tweetnacl2.default.secretbox(dataToEncrypt, nonce, derivedKey);

  if (encryptedData === null || encryptedData === undefined) {
    throw new Error('Password is invalid');
  }

  return encodeEncryptedData(encryptedData, nonce);
}

function encryptData(payload) {
  var data = payload.data,
      derivedKey = payload.derivedKey,
      encryptionType = payload.encryptionType,
      isPrivateKey = payload.isPrivateKey;


  if (encryptionType !== 'nacl.secretbox') {
    throw new Error('Encryption type ' + encryptionType + ' is not supported');
  }

  return encryptNaclSecretbox(data, derivedKey, isPrivateKey);
}

function decodeEncryptedData(data) {
  return {
    data: _tweetnaclUtil2.default.decodeBase64(data.data),
    nonce: _tweetnaclUtil2.default.decodeBase64(data.nonce)
  };
}

function encodePrivateKey(privateKey) {
  var privateKeyBase = _tweetnaclUtil2.default.encodeBase64(privateKey);

  return Buffer.from(privateKeyBase, 'base64').toString();
}

function decryptNaclSecretbox(data, derivedKey, isPrivateKey) {
  var decoded = decodeEncryptedData(data);
  var decryptedData = _tweetnacl2.default.secretbox.open(decoded.data, decoded.nonce, derivedKey);

  if (decryptedData === null || decryptedData === undefined) {
    throw new Error('Password is invalid');
  }

  return isPrivateKey ? encodePrivateKey(decryptedData) : _tweetnaclUtil2.default.encodeUTF8(decryptedData);
}

function decryptData(payload) {
  var data = payload.data,
      derivedKey = payload.derivedKey,
      encryptionType = payload.encryptionType,
      isPrivateKey = payload.isPrivateKey;


  if (encryptionType !== 'nacl.secretbox') {
    throw new Error('Decryption type ' + encryptionType + ' is not supported');
  }

  return decryptNaclSecretbox(data, derivedKey, isPrivateKey);
}