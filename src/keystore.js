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
const DEFAULT_ENCRYPTION_TYPE: string = 'nacl.secretbox'
const DEFAULT_DERIVATION_PATH: string = 'm/44\'/60\'/0\'/0'
const PADDED_MNEMONIC_LENGTH: number = 120
const DEFAULT_SALT_BYTES_COUNT: number = 32
const DEFAULT_DERIVATION_KEY_LENGTH: number = 32

export {
  testPassword,
  generateMnemonic,
  checkMnemonicValid,
  checkBip32XPublicKeyValid,
}

export function getPasswordOptions(options: ?PasswordOptionsUser): PasswordOptions {
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

export function getMnemonicOptions(options: ?MnemonicOptionsUser): MnemonicOptions {
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

export function getHdPath(mnemonic: string, mnemonicOptions: MnemonicOptions): string {
  const {
    network,
    passphrase,
    derivationPath,
  }: MnemonicOptions = mnemonicOptions

  const hdRoot: string = new Mnemonic(mnemonic.trim()).toHDPrivateKey(passphrase, network).xprivkey
  const hdRootKey: HDPrivateKey = new bitcore.HDPrivateKey(hdRoot)

  return hdRootKey.derive(derivationPath).xprivkey
}

export function getPrivateHdRoot(mnemonic: string, mnemonicOptions: MnemonicOptions): HDPrivateKey {
  const hdPath: string = getHdPath(mnemonic, mnemonicOptions)

  return new bitcore.HDPrivateKey(hdPath)
}

export function getPublicHdRoot(bip32XPublicKey: string): HDPublicKey {
  return new bitcore.HDPublicKey(bip32XPublicKey)
}

export function deriveKeyFromPassword(
  password: string,
  salt: string,
  scryptParams: ScryptParams,
): Uint8Array {
  return utils.deriveKeyFromPassword(password, scryptParams, DEFAULT_DERIVATION_KEY_LENGTH, salt)
}

export function encryptData(
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

export function decryptData(
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

export function checkAddressValid(address: string): boolean {
  return utils.checkAddressValid(address)
}

export function checkChecksumAddressValid(address: string): boolean {
  return utils.checkChecksumAddressValid(address)
}

export function checkPrivateKeyValid(privateKey: string): boolean {
  return utils.checkPrivateKeyValid(privateKey)
}

export function checkDerivationPathValid(derivationPath: string): boolean {
  return bitcore.HDPrivateKey.isValidPath(derivationPath)
}

export function checkWalletIsNotReadOnly(isReadOnly: boolean): void {
  if (isReadOnly) {
    throw new Error('Wallet is read only')
  }
}

export function getAddressFromPrivateKey(privateKey: string): string {
  return utils.getAddressFromPrivateKey(privateKey)
}

export function getXPubFromMnemonic(
  mnemonic: string,
  mnemonicOptionsUser: MnemonicOptionsUser,
): string {
  const mnemonicOptions: MnemonicOptions = getMnemonicOptions(mnemonicOptionsUser)
  const hdRoot: HDPrivateKey = getPrivateHdRoot(mnemonic, mnemonicOptions)

  return hdRoot.hdPublicKey.toString()
}

export function encryptMnemonic(
  mnemonic: string,
  password: string,
  passwordOptionsUser?: ?PasswordOptionsUser,
): EncryptedData {
  const mnemonicPad: string = utils.leftPadString(mnemonic, ' ', PADDED_MNEMONIC_LENGTH)
  const passwordOptions: PasswordOptions = getPasswordOptions(passwordOptionsUser)

  const {
    salt,
    scryptParams,
    encryptionType,
  } = passwordOptions

  const derivedKey: Uint8Array = deriveKeyFromPassword(password, salt, scryptParams)

  return encryptData(mnemonicPad, derivedKey, encryptionType, false)
}

export function encryptPrivateKey(
  privateKey: string,
  password: string,
  passwordOptionsUser?: ?PasswordOptionsUser,
): EncryptedData {
  const passwordOptions: PasswordOptions = getPasswordOptions(passwordOptionsUser)

  const {
    salt,
    scryptParams,
    encryptionType,
  } = passwordOptions

  const derivedKey: Uint8Array = deriveKeyFromPassword(password, salt, scryptParams)

  return encryptData(privateKey, derivedKey, encryptionType, true)
}

export function decryptMnemonic(
  mnemonic: EncryptedData,
  password: string,
  passwordOptionsUser?: ?PasswordOptionsUser,
): string {
  const passwordOptions: PasswordOptions = getPasswordOptions(passwordOptionsUser)

  const {
    salt,
    scryptParams,
    encryptionType,
  } = passwordOptions

  const derivedKey: Uint8Array = deriveKeyFromPassword(password, salt, scryptParams)
  const mnemonicPad: string = decryptData(mnemonic, derivedKey, encryptionType, true)

  return mnemonicPad.trim()
}

export function decryptPrivateKey(
  privateKey: EncryptedData,
  password: string,
  passwordOptionsUser?: ?PasswordOptionsUser,
): string {
  const passwordOptions: PasswordOptions = getPasswordOptions(passwordOptionsUser)

  const {
    salt,
    scryptParams,
    encryptionType,
  } = passwordOptions

  const derivedKey: Uint8Array = deriveKeyFromPassword(password, salt, scryptParams)

  return decryptData(privateKey, derivedKey, encryptionType, true)
}

export function getPrivateKeyFromMnemonic(
  mnemonic: string,
  addressIndex: number,
  mnemonicOptions: MnemonicOptions,
): string {
  const hdRoot: HDPrivateKey = getPrivateHdRoot(mnemonic, mnemonicOptions)
  const generatedKey: HDPrivateKey = hdRoot.derive(addressIndex)

  return generatedKey.privateKey.toString()
}

export function generateAddress(hdRoot: HDPublicKey, index: number): string {
  const generatedKey: HDPublicKey = hdRoot.derive(index)
  const publicKey: string = generatedKey.publicKey.toString()

  return utils.getAddressFromPublicKey(publicKey)
}

export function generateAddresses(
  bip32XPublicKey: string,
  start: ?number,
  end: ?number,
): Array<string> {
  const hdRoot: HDPublicKey = getPublicHdRoot(bip32XPublicKey)
  const startIndex: number = start || 0
  const endIndex: number = end || startIndex
  const addressesCount: number = endIndex - startIndex

  // generate range from 0 to addressesCount
  return Array
    .from(new Array(addressesCount + 1).keys())
    .map((currentIndex: number): string => generateAddress(hdRoot, startIndex + currentIndex))
}
