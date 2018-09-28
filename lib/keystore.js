'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.checkBip32XPublicKeyValid = exports.checkMnemonicValid = exports.generateMnemonic = exports.testPassword = undefined;
exports.generateSalt = generateSalt;
exports.leftPadString = leftPadString;
exports.getPasswordOptions = getPasswordOptions;
exports.getMnemonicOptions = getMnemonicOptions;
exports.getHdPath = getHdPath;
exports.getPrivateHdRoot = getPrivateHdRoot;
exports.getPublicHdRoot = getPublicHdRoot;
exports.deriveKeyFromPassword = deriveKeyFromPassword;
exports.encryptData = encryptData;
exports.decryptData = decryptData;
exports.checkAddressValid = checkAddressValid;
exports.checkChecksumAddressValid = checkChecksumAddressValid;
exports.checkPrivateKeyValid = checkPrivateKeyValid;
exports.checkDerivationPathValid = checkDerivationPathValid;
exports.checkWalletIsNotReadOnly = checkWalletIsNotReadOnly;
exports.getAddressFromPrivateKey = getAddressFromPrivateKey;
exports.getXPubFromMnemonic = getXPubFromMnemonic;
exports.encryptMnemonic = encryptMnemonic;
exports.encryptPrivateKey = encryptPrivateKey;
exports.decryptMnemonic = decryptMnemonic;
exports.decryptPrivateKey = decryptPrivateKey;
exports.getPrivateKeyFromMnemonic = getPrivateKeyFromMnemonic;
exports.generateAddress = generateAddress;
exports.generateAddresses = generateAddresses;

var _bitcoreLib = require('bitcore-lib');

var _bitcoreLib2 = _interopRequireDefault(_bitcoreLib);

var _bitcoreMnemonic = require('bitcore-mnemonic');

var _bitcoreMnemonic2 = _interopRequireDefault(_bitcoreMnemonic);

var _password = require('./password');

var _mnemonic = require('./mnemonic');

var _utils = require('./utils');

var utils = _interopRequireWildcard(_utils);

var _encryption = require('./encryption');

var encryption = _interopRequireWildcard(_encryption);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var DEFAULT_SCRYPT_PARAMS = {
  N: Math.pow(2, 18),
  r: 8,
  p: 1
};

var DEFAULT_NETWORK = 'livenet';
var DEFAULT_ENCRYPTION_TYPE = 'nacl.secretbox';
var DEFAULT_DERIVATION_PATH = 'm/44\'/60\'/0\'/0';
var PADDED_MNEMONIC_LENGTH = 120;
var DEFAULT_SALT_BYTES_COUNT = 32;
var DEFAULT_DERIVATION_KEY_LENGTH = 32;

exports.testPassword = _password.testPassword;
exports.generateMnemonic = _mnemonic.generateMnemonic;
exports.checkMnemonicValid = _mnemonic.checkMnemonicValid;
exports.checkBip32XPublicKeyValid = _mnemonic.checkBip32XPublicKeyValid;
function generateSalt(byteCount) {
  return utils.generateSalt(byteCount);
}

function leftPadString(stringToPad, padChar, totalLength) {
  return utils.leftPadString(stringToPad, padChar, totalLength);
}

function getPasswordOptions(options) {
  var salt = generateSalt(DEFAULT_SALT_BYTES_COUNT);

  return !options ? {
    salt: salt,
    passwordHint: null,
    scryptParams: DEFAULT_SCRYPT_PARAMS,
    encryptionType: DEFAULT_ENCRYPTION_TYPE
  } : {
    salt: salt,
    passwordHint: options.passwordHint,
    scryptParams: options.scryptParams || DEFAULT_SCRYPT_PARAMS,
    encryptionType: options.encryptionType || DEFAULT_ENCRYPTION_TYPE
  };
}

function getMnemonicOptions(options) {
  return !options ? {
    passphrase: '',
    network: DEFAULT_NETWORK,
    derivationPath: DEFAULT_DERIVATION_PATH,
    paddedMnemonicLength: PADDED_MNEMONIC_LENGTH
  } : {
    passphrase: options.passphrase || '',
    network: options.network || DEFAULT_NETWORK,
    derivationPath: options.derivationPath || DEFAULT_DERIVATION_PATH,
    paddedMnemonicLength: options.paddedMnemonicLength || PADDED_MNEMONIC_LENGTH
  };
}

function getHdPath(mnemonic, mnemonicOptions) {
  var network = mnemonicOptions.network,
      passphrase = mnemonicOptions.passphrase,
      derivationPath = mnemonicOptions.derivationPath;


  var hdRoot = new _bitcoreMnemonic2.default(mnemonic.trim()).toHDPrivateKey(passphrase, network).xprivkey;
  var hdRootKey = new _bitcoreLib2.default.HDPrivateKey(hdRoot);

  return hdRootKey.derive(derivationPath).xprivkey;
}

function getPrivateHdRoot(mnemonic, mnemonicOptions) {
  var hdPath = getHdPath(mnemonic, mnemonicOptions);

  return new _bitcoreLib2.default.HDPrivateKey(hdPath);
}

function getPublicHdRoot(bip32XPublicKey) {
  return new _bitcoreLib2.default.HDPublicKey(bip32XPublicKey);
}

function deriveKeyFromPassword(password, salt, scryptParams) {
  return utils.deriveKeyFromPassword(password, scryptParams, DEFAULT_DERIVATION_KEY_LENGTH, salt);
}

function encryptData(dataToEncrypt, derivedKey, encryptionType, isPrivateKey) {
  return encryption.encryptData({
    derivedKey: derivedKey,
    encryptionType: encryptionType,
    data: dataToEncrypt,
    isPrivateKey: !!isPrivateKey
  });
}

function decryptData(dataToDecrypt, derivedKey, encryptionType, isPrivateKey) {
  return encryption.decryptData({
    derivedKey: derivedKey,
    encryptionType: encryptionType,
    data: dataToDecrypt,
    isPrivateKey: !!isPrivateKey
  });
}

function checkAddressValid(address) {
  return utils.checkAddressValid(address);
}

function checkChecksumAddressValid(address) {
  return utils.checkChecksumAddressValid(address);
}

function checkPrivateKeyValid(privateKey) {
  return utils.checkPrivateKeyValid(privateKey);
}

function checkDerivationPathValid(derivationPath) {
  return _bitcoreLib2.default.HDPrivateKey.isValidPath(derivationPath);
}

function checkWalletIsNotReadOnly(isReadOnly) {
  if (isReadOnly) {
    throw new Error('Wallet is read only');
  }
}

function getAddressFromPrivateKey(privateKey) {
  return utils.getAddressFromPrivateKey(privateKey);
}

function getXPubFromMnemonic(mnemonic, mnemonicOptionsUser) {
  var mnemonicOptions = getMnemonicOptions(mnemonicOptionsUser);
  var hdRoot = getPrivateHdRoot(mnemonic, mnemonicOptions);

  return hdRoot.hdPublicKey.toString();
}

function encryptMnemonic(mnemonic, password, passwordOptionsUser) {
  var mnemonicPad = leftPadString(mnemonic, ' ', PADDED_MNEMONIC_LENGTH);
  var passwordOptions = getPasswordOptions(passwordOptionsUser);

  var salt = passwordOptions.salt,
      scryptParams = passwordOptions.scryptParams,
      encryptionType = passwordOptions.encryptionType;


  var derivedKey = deriveKeyFromPassword(password, salt, scryptParams);

  return encryptData(mnemonicPad, derivedKey, encryptionType, false);
}

function encryptPrivateKey(privateKey, password, passwordOptionsUser) {
  var passwordOptions = getPasswordOptions(passwordOptionsUser);

  var salt = passwordOptions.salt,
      scryptParams = passwordOptions.scryptParams,
      encryptionType = passwordOptions.encryptionType;


  var derivedKey = deriveKeyFromPassword(password, salt, scryptParams);

  return encryptData(privateKey, derivedKey, encryptionType, true);
}

function decryptMnemonic(mnemonic, password, passwordOptionsUser) {
  var passwordOptions = getPasswordOptions(passwordOptionsUser);

  var salt = passwordOptions.salt,
      scryptParams = passwordOptions.scryptParams,
      encryptionType = passwordOptions.encryptionType;


  var derivedKey = deriveKeyFromPassword(password, salt, scryptParams);
  var mnemonicPad = decryptData(mnemonic, derivedKey, encryptionType, true);

  return mnemonicPad.trim();
}

function decryptPrivateKey(privateKey, password, passwordOptionsUser) {
  var passwordOptions = getPasswordOptions(passwordOptionsUser);

  var salt = passwordOptions.salt,
      scryptParams = passwordOptions.scryptParams,
      encryptionType = passwordOptions.encryptionType;


  var derivedKey = deriveKeyFromPassword(password, salt, scryptParams);

  return decryptData(privateKey, derivedKey, encryptionType, true);
}

function getPrivateKeyFromMnemonic(mnemonic, addressIndex, mnemonicOptions) {
  var hdRoot = getPrivateHdRoot(mnemonic, mnemonicOptions);
  var generatedKey = hdRoot.derive(addressIndex);

  return generatedKey.privateKey.toString();
}

function generateAddress(hdRoot, index) {
  var generatedKey = hdRoot.derive(index);
  var publicKey = generatedKey.publicKey.toString();

  return utils.getAddressFromPublicKey(publicKey);
}

function generateAddresses(bip32XPublicKey, start, end) {
  var hdRoot = getPublicHdRoot(bip32XPublicKey);
  var startIndex = start || 0;
  var endIndex = end || startIndex;
  var addressesCount = endIndex - startIndex;

  // generate range from 0 to addressesCount
  return Array.from(new Array(addressesCount + 1).keys()).map(function (currentIndex) {
    return generateAddress(hdRoot, startIndex + currentIndex);
  });
}