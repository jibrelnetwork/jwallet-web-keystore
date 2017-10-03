'use strict';

var Mnemonic = require('bitcore-mnemonic');
var bitcore = require('bitcore-lib');

var _bitcore$crypto = bitcore.crypto,
    Random = _bitcore$crypto.Random,
    Hash = _bitcore$crypto.Hash;


var BIP32_EXTENDABLE_PUBLIC_KEY_LENGTH = 111;

function generateMnemonic(entropy, randomBufferLength) {
  var dataList = Mnemonic.Words.ENGLISH;
  var hashedEntropy = getHashedEntropy(entropy, randomBufferLength);

  var mnemonic = hashedEntropy ? new Mnemonic(hashedEntropy, dataList) : new Mnemonic(dataList);

  return mnemonic;
}

function isMnemonicValid(mnemonic) {
  return Mnemonic.isValid(mnemonic, Mnemonic.Words.ENGLISH);
}

function isBip32XPublicKeyValid(bip32XPublicKey) {
  if (!bip32XPublicKey) {
    return false;
  }

  if (bip32XPublicKey.length !== BIP32_EXTENDABLE_PUBLIC_KEY_LENGTH) {
    return false;
  }

  var re = new RegExp('^(xpub)([A-Z\\d]{' + (BIP32_EXTENDABLE_PUBLIC_KEY_LENGTH - 4) + '})$', 'i');

  return re.test(bip32XPublicKey);
}

function getHashedEntropy(entropy, randomBufferLength) {
  if (!entropy) {
    return null;
  } else if (typeof entropy !== 'string') {
    throw new Error('Entropy is set but not a string.');
  }

  var entropyBuffer = Buffer.from(entropy);
  var randomBuffer = Random.getRandomBuffer(randomBufferLength);

  return concatEntropyBuffers(entropyBuffer, randomBuffer).slice(0, 16);
}

function concatEntropyBuffers(entropyBuffer, randomBuffer) {
  var totalEntropy = Buffer.concat([entropyBuffer, randomBuffer]);

  if (totalEntropy.length !== entropyBuffer.length + randomBuffer.length) {
    throw new Error('Concatenation of entropy buffers failed.');
  }

  return Hash.sha256(totalEntropy);
}

module.exports = { generateMnemonic: generateMnemonic, isMnemonicValid: isMnemonicValid, isBip32XPublicKeyValid: isBip32XPublicKeyValid };