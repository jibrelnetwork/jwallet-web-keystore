'use strict';

function _objectWithoutProperties(obj, keys) { var target = {}; for (var i in obj) { if (keys.indexOf(i) >= 0) continue; if (!Object.prototype.hasOwnProperty.call(obj, i)) continue; target[i] = obj[i]; } return target; }

var nacl = require('tweetnacl');
var util = require('tweetnacl-util');

var randomBytes = nacl.randomBytes,
    secretbox = nacl.secretbox;


function encryptData(props) {
  var encryptionType = props.encryptionType,
      otherProps = _objectWithoutProperties(props, ['encryptionType']);

  if (encryptionType === 'nacl.secretbox') {
    return encryptNaclSecretbox(otherProps);
  }

  throw new Error('Encryption type ' + encryptionType + ' is not supported');
}

function encryptNaclSecretbox(props) {
  var data = props.data,
      derivedKey = props.derivedKey,
      isPrivateKey = props.isPrivateKey;


  var nonce = getNonce();
  var dataToEncrypt = isPrivateKey ? decodePrivateKey(data) : util.decodeUTF8(data);
  var encryptedData = secretbox(dataToEncrypt, nonce, derivedKey);

  return encodeEncryptedData(encryptedData, nonce, 'nacl.secretbox');
}

function encodeEncryptedData(encryptedData, nonce, encryptionType) {
  return {
    encryptionType: encryptionType,
    nonce: util.encodeBase64(nonce),
    encryptedData: util.encodeBase64(encryptedData)
  };
}

function decodeEncryptedData(data) {
  return {
    encryptedData: util.decodeBase64(data.encryptedData),
    nonce: util.decodeBase64(data.nonce)
  };
}

function getNonce() {
  return randomBytes(secretbox.nonceLength);
}

function decodePrivateKey(privateKey) {
  var privateKeyBase64 = Buffer.from(privateKey).toString('base64');

  return util.decodeBase64(privateKeyBase64);
}

function encodePrivateKey(privateKey) {
  var privateKeyBase64 = util.encodeBase64(privateKey);

  return Buffer.from(privateKeyBase64, 'base64').toString();
}

function decryptData(props) {
  var encryptionType = props.data.encryptionType;


  if (encryptionType === 'nacl.secretbox') {
    return decryptNaclSecretbox(props);
  }

  throw new Error('Decryption type ' + encryptionType + ' is not supported');
}

function decryptNaclSecretbox(props) {
  var data = props.data,
      derivedKey = props.derivedKey,
      isPrivateKey = props.isPrivateKey;

  var _decodeEncryptedData = decodeEncryptedData(data),
      nonce = _decodeEncryptedData.nonce,
      encryptedData = _decodeEncryptedData.encryptedData;

  var decryptedData = secretbox.open(encryptedData, nonce, derivedKey);

  if (decryptedData == null) {
    throw new Error('Decryption failed');
  }

  return isPrivateKey ? encodePrivateKey(decryptedData) : util.encodeUTF8(decryptedData);
}

module.exports = { encryptData: encryptData, decryptData: decryptData };