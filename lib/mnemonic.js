'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.generateMnemonic = generateMnemonic;
exports.checkMnemonicValid = checkMnemonicValid;
exports.checkBip32XPublicKeyValid = checkBip32XPublicKeyValid;

var _bitcoreMnemonic = require('bitcore-mnemonic');

var _bitcoreMnemonic2 = _interopRequireDefault(_bitcoreMnemonic);

var _bitcoreLib = require('bitcore-lib');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var DEFAULT_RANDOM_BUFFER_LENGTH = 32;
var BIP32_EXTENDABLE_PUBLIC_KEY_LENGTH = 111;
var ENGLISH_WORDS = _bitcoreMnemonic2.default.Words.ENGLISH;

function concatEntropyBuffers(entropyBuffer, randomBuffer) {
  var totalEntropy = Buffer.concat([entropyBuffer, randomBuffer]);

  if (totalEntropy.length !== entropyBuffer.length + randomBuffer.length) {
    throw new Error('Concatenation of entropy buffers failed.');
  }

  return _bitcoreLib.crypto.Hash.sha256(totalEntropy);
}

function getHashedEntropy(entropy, randomBufferLength) {
  if (!entropy) {
    return null;
  } else if (typeof entropy !== 'string') {
    throw new TypeError('Entropy is set but not a string.');
  }

  var entropyBuffer = Buffer.from(entropy);
  var randomBuffer = _bitcoreLib.crypto.Random.getRandomBuffer(randomBufferLength);

  return concatEntropyBuffers(entropyBuffer, randomBuffer).slice(0, 16);
}

function generateMnemonic(entropy) {
  var randomBufferLength = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : DEFAULT_RANDOM_BUFFER_LENGTH;

  var hashedEntropy = getHashedEntropy(entropy, randomBufferLength);

  var mnemonic = hashedEntropy ? new _bitcoreMnemonic2.default(hashedEntropy, ENGLISH_WORDS) : new _bitcoreMnemonic2.default(ENGLISH_WORDS);

  return mnemonic.toString();
}

function checkMnemonicValid(mnemonic) {
  return _bitcoreMnemonic2.default.isValid(mnemonic, ENGLISH_WORDS);
}

function checkBip32XPublicKeyValid(bip32XPublicKey) {
  if (!bip32XPublicKey || bip32XPublicKey.length !== BIP32_EXTENDABLE_PUBLIC_KEY_LENGTH) {
    return false;
  }

  var reLengthWithoutXPUB = BIP32_EXTENDABLE_PUBLIC_KEY_LENGTH - 4;
  var re = new RegExp('^(xpub)([A-Z\\d]{' + reLengthWithoutXPUB + '})$', 'i');

  return re.test(bip32XPublicKey);
}