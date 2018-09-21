// @flow

import bitcore from 'bitcore-lib'
import Mnemonic from 'bitcore-mnemonic'

import { testPassword } from './password'
import { generateMnemonic, checkMnemonicValid, checkBip32XPublicKeyValid } from './mnemonic'
import * as utils from './utils'
import * as encryption from './encryption'

type HDPublicKey = {|
  +toString: () => string,
  +derive: (number) => HDPublicKey,
  +xpubkey: string,
  +publicKey: {|
    +toString: () => string,
  |},
|}

type HDPrivateKey = {|
  +toString: () => string,
  +isValidPath: (string) => boolean,
  +derive: (string | number) => HDPrivateKey,
  +xpubkey: string,
  +xprivkey: string,
  +hdPublicKey: HDPublicKey,
  +privateKey: {|
    +toString: () => string,
  |},
|}

const DEFAULT_SCRYPT_PARAMS: ScryptParams = {
  N: 2 ** 18,
  r: 8,
  p: 1,
}

const DEFAULT_NETWORK: string = 'livenet'
const ADDRESS_TYPE: 'address' = 'address'
const MNEMONIC_TYPE: 'mnemonic' = 'mnemonic'
const DEFAULT_ENCRYPTION_TYPE: string = 'nacl.secretbox'
const DEFAULT_DERIVATION_PATH: string = 'm/44\'/60\'/0\'/0'
const PADDED_MNEMONIC_LENGTH: number = 120
const TEST_PASSWORD_DATA_LENGTH: number = 120
const DEFAULT_SALT_BYTES_COUNT: number = 32
const DEFAULT_DERIVATION_KEY_LENGTH: number = 32

function _getPasswordOptions(options: ?PasswordOptionsUser): PasswordOptions {
  const salt: string = utils.generateSalt(DEFAULT_SALT_BYTES_COUNT)

  return !options
    ? {
      salt,
      passwordHint: null,
      scryptParams: DEFAULT_SCRYPT_PARAMS,
      encryptionType: DEFAULT_ENCRYPTION_TYPE,
    }
    : {
      salt,
      passwordHint: options.passwordHint,
      scryptParams: options.scryptParams || DEFAULT_SCRYPT_PARAMS,
      encryptionType: options.encryptionType || DEFAULT_ENCRYPTION_TYPE,
    }
}

function _getMnemonicOptions(options: ?MnemonicOptionsUser): MnemonicOptions {
  return !options ? {
    passphrase: '',
    network: DEFAULT_NETWORK,
    derivationPath: DEFAULT_DERIVATION_PATH,
    paddedMnemonicLength: PADDED_MNEMONIC_LENGTH,
  } : {
    passphrase: options.passphrase || '',
    network: options.network || DEFAULT_NETWORK,
    derivationPath: options.derivationPath || DEFAULT_DERIVATION_PATH,
    paddedMnemonicLength: options.paddedMnemonicLength || PADDED_MNEMONIC_LENGTH,
  }
}

function _getHdPath(mnemonic: string, mnemonicOptions: MnemonicOptions): string {
  const {
    network,
    passphrase,
    derivationPath,
  }: MnemonicOptions = mnemonicOptions

  const hdRoot: string = new Mnemonic(mnemonic.trim()).toHDPrivateKey(passphrase, network).xprivkey
  const hdRootKey: HDPrivateKey = new bitcore.HDPrivateKey(hdRoot)

  return hdRootKey.derive(derivationPath).xprivkey
}

function _getPrivateHdRoot(mnemonic: string, mnemonicOptions: MnemonicOptions): HDPrivateKey {
  const hdPath: string = _getHdPath(mnemonic, mnemonicOptions)

  return new bitcore.HDPrivateKey(hdPath)
}

function _getPublicHdRoot(bip32XPublicKey: string): HDPublicKey {
  return new bitcore.HDPublicKey(bip32XPublicKey)
}

function _deriveKeyFromPassword(
  password: string,
  salt: string,
  scryptParams: ScryptParams,
): Uint8Array {
  return utils.deriveKeyFromPassword(password, scryptParams, DEFAULT_DERIVATION_KEY_LENGTH, salt)
}

function _encryptData(
  dataToEncrypt: string,
  derivedKey: Uint8Array,
  encryptionType: string,
  isPrivateKey?: boolean,
): EncryptedData {
  return encryption.encryptData({
    derivedKey,
    encryptionType,
    data: dataToEncrypt,
    isPrivateKey: !!isPrivateKey,
  })
}

function _decryptData(
  dataToDecrypt: EncryptedData,
  derivedKey: Uint8Array,
  encryptionType: string,
  isPrivateKey?: boolean,
): string {
  return encryption.decryptData({
    derivedKey,
    encryptionType,
    data: dataToDecrypt,
    isPrivateKey: !!isPrivateKey,
  })
}

function _testPassword(password: string): void {
  const testPasswordResult: PasswordResult = testPassword(password)

  if (testPasswordResult.score < 3) {
    throw new Error(testPasswordResult.feedback.warning)
  }
}

function _reEncryptWallet(
  wallet: Wallet,
  derivedKey: Uint8Array,
  newDerivedKey: Uint8Array,
  encryptionType: string,
  newEncryptionType: string,
): Wallet {
  const {
    type,
    encrypted,
    isReadOnly,
  }: Wallet = wallet

  if (isReadOnly) {
    return wallet
  }

  if ((type === MNEMONIC_TYPE) && encrypted.mnemonic) {
    const mnemonicDec: string = _decryptData(encrypted.mnemonic, derivedKey, encryptionType)

    return {
      ...wallet,
      encrypted: {
        ...encrypted,
        mnemonic: _encryptData(mnemonicDec, newDerivedKey, newEncryptionType),
      },
    }
  } else if ((type === ADDRESS_TYPE) && encrypted.privateKey) {
    const privateKeyDec: string = _decryptData(encrypted.privateKey, derivedKey, encryptionType)

    return {
      ...wallet,
      encrypted: {
        ...encrypted,
        privateKey: _encryptData(privateKeyDec, newDerivedKey, newEncryptionType),
      },
    }
  }

  return wallet
}

function _reEncryptWallets(
  wallets: Wallets,
  derivedKey: Uint8Array,
  newDerivedKey: Uint8Array,
  encryptionType: string,
  newEncryptionType: string,
): Wallets {
  return wallets.map((wallet: Wallet): Wallet => _reEncryptWallet(
    wallet,
    derivedKey,
    newDerivedKey,
    encryptionType,
    newEncryptionType,
  ))
}

function checkAddressValid(address: string): boolean {
  return utils.checkAddressValid(address)
}

function checkChecksumAddressValid(address: string): boolean {
  return utils.checkChecksumAddressValid(address)
}

function checkPrivateKeyValid(privateKey: string): boolean {
  return utils.checkPrivateKeyValid(privateKey)
}

function checkDerivationPathValid(derivationPath: string): boolean {
  return bitcore.HDPrivateKey.isValidPath(derivationPath)
}

function checkWalletIsNotReadOnly(isReadOnly: boolean): void {
  if (isReadOnly) {
    throw new Error('Wallet is read only')
  }
}

function checkWalletIsMnemonicType(type: WalletType): void {
  if (type !== MNEMONIC_TYPE) {
    throw new Error('Wallet type is not mnemonic')
  }
}

function checkWalletUniqueness(
  wallets: Wallets,
  uniqueProperty: string,
  propertyName: string,
): void {
  const foundWallet: ?Wallet = wallets.find((wallet: Wallet): boolean => {
    const propertyValue: string = wallet[propertyName]

    return propertyValue ? (propertyValue.toLowerCase() === uniqueProperty.toLowerCase()) : false
  })

  if (foundWallet) {
    throw new Error(`Wallet with this ${propertyName} already exists`)
  }
}

function getAddressFromPrivateKey(privateKey: string): string {
  return utils.getAddressFromPrivateKey(privateKey)
}

function getXPubFromMnemonic(mnemonic: string, mnemonicOptionsUser: MnemonicOptionsUser): string {
  const mnemonicOptions: MnemonicOptions = _getMnemonicOptions(mnemonicOptionsUser)
  const hdRoot: HDPrivateKey = _getPrivateHdRoot(mnemonic, mnemonicOptions)

  return hdRoot.hdPublicKey.toString()
}

function encryptMnemonic(
  mnemonic: string,
  password: string,
  passwordOptionsUser?: ?PasswordOptionsUser,
): EncryptedData {
  const mnemonicPad: string = utils.leftPadString(mnemonic, ' ', PADDED_MNEMONIC_LENGTH)
  const passwordOptions: PasswordOptions = _getPasswordOptions(passwordOptionsUser)

  const {
    salt,
    scryptParams,
    encryptionType,
  } = passwordOptions

  const derivedKey: Uint8Array = _deriveKeyFromPassword(password, salt, scryptParams)

  return _encryptData(mnemonicPad, derivedKey, encryptionType, false)
}

function encryptPrivateKey(
  privateKey: string,
  password: string,
  passwordOptionsUser?: ?PasswordOptionsUser,
): EncryptedData {
  const passwordOptions: PasswordOptions = _getPasswordOptions(passwordOptionsUser)

  const {
    salt,
    scryptParams,
    encryptionType,
  } = passwordOptions

  const derivedKey: Uint8Array = _deriveKeyFromPassword(password, salt, scryptParams)

  return _encryptData(privateKey, derivedKey, encryptionType, true)
}

function decryptMnemonic(
  mnemonic: EncryptedData,
  password: string,
  passwordOptionsUser?: ?PasswordOptionsUser,
): string {
  const passwordOptions: PasswordOptions = _getPasswordOptions(passwordOptionsUser)

  const {
    salt,
    scryptParams,
    encryptionType,
  } = passwordOptions

  const derivedKey: Uint8Array = _deriveKeyFromPassword(password, salt, scryptParams)
  const mnemonicPad: string = _decryptData(mnemonic, derivedKey, encryptionType, true)

  return mnemonicPad.trim()
}

function decryptPrivateKey(
  privateKey: EncryptedData,
  password: string,
  passwordOptionsUser?: ?PasswordOptionsUser,
): string {
  const passwordOptions: PasswordOptions = _getPasswordOptions(passwordOptionsUser)

  const {
    salt,
    scryptParams,
    encryptionType,
  } = passwordOptions

  const derivedKey: Uint8Array = _deriveKeyFromPassword(password, salt, scryptParams)

  return _decryptData(privateKey, derivedKey, encryptionType, true)
}

function getPrivateKeyFromMnemonic(
  mnemonic: string,
  addressIndex: number,
  mnemonicOptions: MnemonicOptions,
): string {
  const hdRoot: HDPrivateKey = _getPrivateHdRoot(mnemonic, mnemonicOptions)
  const generatedKey: HDPrivateKey = hdRoot.derive(addressIndex)

  return generatedKey.privateKey.toString()
}

function generateAddress(hdRoot: HDPublicKey, index: number): string {
  const generatedKey: HDPublicKey = hdRoot.derive(index)
  const publicKey: string = generatedKey.publicKey.toString()

  return utils.getAddressFromPublicKey(publicKey)
}

function generateAddresses(bip32XPublicKey: string, start: ?number, end: ?number): Array<string> {
  const hdRoot: HDPublicKey = _getPublicHdRoot(bip32XPublicKey)
  const startIndex: number = start || 0
  const endIndex: number = end || startIndex
  const addressesCount: number = endIndex - startIndex

  // generate range from 0 to addressesCount
  return Array
    .from(new Array(addressesCount + 1).keys())
    .map((currentIndex: number): string => generateAddress(hdRoot, startIndex + currentIndex))
}

/**
 * TODO: Move this function into jwallet-web
 */
function initKeystore(password: string, passwordOptionsUser?: ?PasswordOptionsUser): Keystore {
  _testPassword(password)

  const passwordOptions: PasswordOptions = _getPasswordOptions(passwordOptionsUser)

  const {
    salt,
    scryptParams,
    encryptionType,
  }: PasswordOptions = passwordOptions

  const testPasswordData: string = utils.generateSalt(TEST_PASSWORD_DATA_LENGTH)
  const dKey: Uint8Array = _deriveKeyFromPassword(password, salt, scryptParams)
  const testPasswordDataEnc: EncryptedData = _encryptData(testPasswordData, dKey, encryptionType)

  return {
    wallets: [],
    passwordOptions,
    testPasswordData: testPasswordDataEnc,
  }
}

/**
 * TODO: Move this function into jwallet-web
 */
function setPassword(
  keystore: Keystore,
  password: string,
  newPassword: string,
  passwordOptionsUser?: ?PasswordOptionsUser,
): Keystore {
  const {
    wallets,
    passwordOptions,
    testPasswordData,
  }: Keystore = keystore

  const passwordOptionsNew: PasswordOptions = _getPasswordOptions(passwordOptionsUser)

  const derivedKey: Uint8Array = _deriveKeyFromPassword(
    password,
    passwordOptions.salt,
    passwordOptions.scryptParams,
  )

  const testPasswordDataDec: string = _decryptData(
    testPasswordData,
    derivedKey,
    passwordOptions.encryptionType,
  )

  const derivedKeyNew: Uint8Array = _deriveKeyFromPassword(
    newPassword,
    passwordOptionsNew.salt,
    passwordOptionsNew.scryptParams,
  )

  const testPasswordDataEnc: EncryptedData = _encryptData(
    testPasswordDataDec,
    derivedKeyNew,
    passwordOptionsNew.encryptionType,
  )

  const walletsReEnc: Wallets = _reEncryptWallets(
    wallets,
    derivedKey,
    derivedKeyNew,
    passwordOptions.encryptionType,
    passwordOptionsNew.encryptionType,
  )

  return {
    wallets: walletsReEnc,
    passwordOptions: passwordOptionsNew,
    testPasswordData: testPasswordDataEnc,
  }
}

export default {
  setPassword,
  initKeystore,
  testPassword,
  generateAddress,
  encryptMnemonic,
  decryptMnemonic,
  generateMnemonic,
  generateAddresses,
  encryptPrivateKey,
  decryptPrivateKey,
  checkAddressValid,
  checkMnemonicValid,
  getXPubFromMnemonic,
  checkPrivateKeyValid,
  checkWalletUniqueness,
  getAddressFromPrivateKey,
  checkDerivationPathValid,
  checkWalletIsNotReadOnly,
  checkBip32XPublicKeyValid,
  checkChecksumAddressValid,
  checkWalletIsMnemonicType,
  getPrivateKeyFromMnemonic,
}
