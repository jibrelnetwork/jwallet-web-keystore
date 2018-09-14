// @flow

import uuidv4 from 'uuid/v4'
import bitcore from 'bitcore-lib'
import Mnemonic from 'bitcore-mnemonic'

import { testPassword } from './password'
import { generateMnemonic, checkMnemonicValid, checkBip32XPublicKeyValid } from './mnemonic'
import * as utils from './utils'
import * as encryption from './encryption'

import packageData from '../package.json'

type HDPublicKey = {
  +toString: () => string,
  +derive: (number) => HDPublicKey,
  +xpubkey: string,
  +publicKey: {
    +toString: () => string,
  },
}

type HDPrivateKey = {
  +toString: () => string,
  +isValidPath: (string) => boolean,
  +derive: (string | number) => HDPrivateKey,
  +xpubkey: string,
  +xprivkey: string,
  +hdPublicKey: HDPublicKey,
  +privateKey: {
    +toString: () => string,
  },
}

const DEFAULT_SCRYPT_PARAMS: ScryptParams = {
  N: 2 ** 18,
  r: 8,
  p: 1,
}

const ADDRESS_TYPE: 'address' = 'address'
const MNEMONIC_TYPE: 'mnemonic' = 'mnemonic'
const CURRENT_VERSION = packageData.version
const DEFAULT_ENCRYPTION_TYPE: string = 'nacl.secretbox'
const DEFAULT_DERIVATION_PATH: string = 'm/44\'/60\'/0\'/0'
const PADDED_MNEMONIC_LENGTH: number = 120
const DEFAULT_SALT_BYTES_COUNT: number = 32
const DEFAULT_DERIVATION_KEY_LENGTH: number = 32

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

function _checkNotReadOnly(isReadOnly: boolean): void {
  if (isReadOnly) {
    throw new Error('Wallet is read only')
  }
}

function _checkMnemonicType(type: WalletType): void {
  if (type !== MNEMONIC_TYPE) {
    throw new Error('Wallet type is not mnemonic')
  }
}

function _checkWalletUniqueness(
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

function _getHdPath(mnemonic: string, derivationPath: string): string {
  const hdRoot: string = new Mnemonic(mnemonic.trim()).toHDPrivateKey().xprivkey
  const hdRootKey: HDPrivateKey = new bitcore.HDPrivateKey(hdRoot)

  return hdRootKey.derive(derivationPath).xprivkey
}

function _getPrivateHdRoot(mnemonic: string, derivationPath: ?string): HDPrivateKey {
  const hdPath: string = _getHdPath(mnemonic, derivationPath || DEFAULT_DERIVATION_PATH)

  return new bitcore.HDPrivateKey(hdPath)
}

function _getPublicHdRoot(bip32XPublicKey: string): HDPublicKey {
  return new bitcore.HDPublicKey(bip32XPublicKey)
}

function _getXPubFromMnemonic(mnemonic: string, derivationPath: string): string {
  const hdRoot: HDPrivateKey = _getPrivateHdRoot(mnemonic, derivationPath)

  return hdRoot.hdPublicKey.toString()
}

function _deriveKeyFromPassword(
  password: string,
  salt: ?string,
  scryptParams: ?ScryptParams = DEFAULT_SCRYPT_PARAMS,
  derivedKeyLength: ?number = DEFAULT_DERIVATION_KEY_LENGTH,
): Uint8Array {
  if (!password) {
    throw new Error('Password is empty')
  }

  if (!(salt && scryptParams && derivedKeyLength)) {
    throw new Error('Invalid wallet properties')
  }

  return utils.deriveKeyFromPassword(password, scryptParams, derivedKeyLength, salt)
}

function _encryptData(
  dataToEncrypt: string,
  derivedKey: Uint8Array,
  encryptionType?: ?string,
  isPrivateKey?: boolean,
): EncryptedData {
  return encryption.encryptData({
    derivedKey,
    data: dataToEncrypt,
    isPrivateKey: !!isPrivateKey,
    encryptionType: encryptionType || DEFAULT_ENCRYPTION_TYPE,
  })
}

function _encryptPrivateKey(
  dataToEncrypt: string,
  derivedKey: Uint8Array,
  encryptionType?: string,
): EncryptedData {
  return _encryptData(dataToEncrypt, derivedKey, encryptionType, true)
}

function _appendWallet(wallets: Wallets, wallet: Wallet): Wallets {
  return wallets.concat(wallet)
}

function _createMnemonicWallet(
  wallets: Wallets,
  walletData: WalletData,
  password: ?string,
): Wallets {
  const {
    id,
    data,
    name,
    scryptParams,
    saltBytesCount,
    derivationPath,
    encryptionType,
    derivedKeyLength,
    paddedMnemonicLength,
  } = walletData

  if (!password) {
    throw new Error('Password required')
  }

  const mnemonic: string = data.toLowerCase()

  if (!checkDerivationPathValid(derivationPath)) {
    throw new Error('Invalid derivation path')
  }

  const xpub: string = _getXPubFromMnemonic(mnemonic, derivationPath)

  _checkWalletUniqueness(wallets, xpub, 'bip32XPublicKey')

  const salt: string = utils.generateSalt(saltBytesCount)
  const dKey: Uint8Array = _deriveKeyFromPassword(password, salt, scryptParams, derivedKeyLength)
  const mnemonicPad: string = utils.leftPadString(mnemonic, ' ', paddedMnemonicLength)
  const mnemonicEnc: EncryptedData = _encryptData(mnemonicPad, dKey, encryptionType)

  return _appendWallet(wallets, {
    id,
    name,
    salt,
    scryptParams,
    saltBytesCount,
    derivationPath,
    encryptionType,
    derivedKeyLength,
    addressIndex: 0,
    isReadOnly: false,
    type: MNEMONIC_TYPE,
    bip32XPublicKey: xpub,
    customType: 'mnemonic',
    encrypted: {
      privateKey: null,
      mnemonic: mnemonicEnc,
    },
    /**
     * Another wallet data, necessary for consistency of types
     */
    address: null,
  })
}

function _createReadOnlyMnemonicWallet(wallets: Wallets, walletData: WalletData): Wallets {
  const {
    id,
    data,
    name,
  } = walletData

  _checkWalletUniqueness(wallets, data, 'bip32XPublicKey')

  return _appendWallet(wallets, {
    id,
    name,
    addressIndex: 0,
    isReadOnly: true,
    type: MNEMONIC_TYPE,
    bip32XPublicKey: data,
    customType: 'bip32Xpub',
    encrypted: {
      mnemonic: null,
      privateKey: null,
    },
    /**
     * Another wallet data, necessary for consistency of types
     */
    salt: null,
    address: null,
    scryptParams: null,
    saltBytesCount: null,
    encryptionType: null,
    derivationPath: null,
    derivedKeyLength: null,
  })
}

function _createAddressWallet(
  wallets: Wallets,
  walletData: WalletData,
  password: ?string,
): Wallets {
  const {
    id,
    data,
    name,
    scryptParams,
    encryptionType,
    saltBytesCount,
    derivedKeyLength,
  } = walletData

  if (!password) {
    throw new Error('Password required')
  }

  const address: string = utils.getAddressFromPrivateKey(data)

  _checkWalletUniqueness(wallets, address, 'address')

  const salt: string = utils.generateSalt(saltBytesCount)
  const dKey: Uint8Array = _deriveKeyFromPassword(password, salt, scryptParams, derivedKeyLength)

  return _appendWallet(wallets, {
    id,
    name,
    salt,
    address,
    scryptParams,
    saltBytesCount,
    encryptionType,
    derivedKeyLength,
    isReadOnly: false,
    type: ADDRESS_TYPE,
    customType: 'privateKey',
    encrypted: {
      mnemonic: null,
      privateKey: _encryptPrivateKey(data, dKey, encryptionType),
    },
    /**
     * Another wallet data, necessary for consistency of types
     */
    addressIndex: null,
    derivationPath: null,
    bip32XPublicKey: null,
  })
}

function _createReadOnlyAddressWallet(wallets: Wallets, walletData: WalletData): Wallets {
  const {
    id,
    data,
    name,
  } = walletData

  _checkWalletUniqueness(wallets, data, 'address')

  return _appendWallet(wallets, {
    id,
    name,
    address: data,
    isReadOnly: true,
    type: ADDRESS_TYPE,
    customType: 'address',
    encrypted: {
      mnemonic: null,
      privateKey: null,
    },
    /**
     * Another wallet data, necessary for consistency of types
     */
    salt: null,
    addressIndex: null,
    scryptParams: null,
    saltBytesCount: null,
    derivationPath: null,
    encryptionType: null,
    bip32XPublicKey: null,
    derivedKeyLength: null,
  })
}

function _decryptData(
  dataToDecrypt: EncryptedData,
  derivedKey: Uint8Array,
  encryptionType?: ?string,
  isPrivateKey?: boolean,
): string {
  return encryption.decryptData({
    derivedKey,
    data: dataToDecrypt,
    isPrivateKey: !!isPrivateKey,
    encryptionType: encryptionType || DEFAULT_ENCRYPTION_TYPE,
  })
}

function _decryptPrivateKey(
  dataToDecrypt: EncryptedData,
  derivedKey: Uint8Array,
  encryptionType?: ?string,
): string {
  return _decryptData(dataToDecrypt, derivedKey, encryptionType, true)
}

function _getPrivateKeyFromMnemonic(wallet: Wallet, derivedKey: Uint8Array): string {
  const {
    encrypted,
    addressIndex,
    derivationPath,
    encryptionType,
  }: Wallet = wallet

  if (!encrypted.mnemonic) {
    throw new Error('Data to decrypt not found')
  }

  const mnemonic: string = _decryptData(encrypted.mnemonic, derivedKey, encryptionType)
  const hdRoot: HDPrivateKey = _getPrivateHdRoot(mnemonic.trim(), derivationPath)
  const generatedKey: HDPrivateKey = hdRoot.derive(addressIndex || 0)

  return generatedKey.privateKey.toString()
}

function _generateAddress(hdRoot: HDPublicKey, index: number): string {
  const generatedKey: HDPublicKey = hdRoot.derive(index)
  const publicKey: string = generatedKey.publicKey.toString()

  return utils.getAddressFromPublicKey(publicKey)
}

function _generateAddresses(bip32XPublicKey: string, start: ?number, end: ?number): Array<string> {
  const hdRoot: HDPublicKey = _getPublicHdRoot(bip32XPublicKey)
  const startIndex: number = start || 0
  const endIndex: number = end || startIndex
  const addressesCount: number = endIndex - startIndex

  // generate range from 0 to addressesCount
  return Array
    .from(new Array(addressesCount + 1).keys())
    .map((currentIndex: number): string => _generateAddress(hdRoot, startIndex + currentIndex))
}

function _testPassword(
  password: string,
  passwordConfig?: {
    +minLength?: number,
    +maxLength?: number,
  } | void,
): void {
  const testPasswordResult: PasswordResult = testPassword(password, passwordConfig)

  if (testPasswordResult.failedTests.length) {
    throw new Error(testPasswordResult.errors[0])
  }
}

function _getPasswordOptions(options: {
  +scryptParams?: ScryptParams,
  +encryptionType?: string,
  +saltBytesCount?: number,
  +derivedKeyLength?: number,
} | void): SetPasswordOptions {
  const saltBytesCount: number = options
    ? options.saltBytesCount || DEFAULT_SALT_BYTES_COUNT
    : DEFAULT_SALT_BYTES_COUNT

  const salt: string = utils.generateSalt(saltBytesCount)

  return !options
    ? {
      salt,
      saltBytesCount,
      scryptParams: DEFAULT_SCRYPT_PARAMS,
      encryptionType: DEFAULT_ENCRYPTION_TYPE,
      derivedKeyLength: DEFAULT_DERIVATION_KEY_LENGTH,
    }
    : {
      salt,
      saltBytesCount,
      scryptParams: options.scryptParams || DEFAULT_SCRYPT_PARAMS,
      encryptionType: options.encryptionType || DEFAULT_ENCRYPTION_TYPE,
      derivedKeyLength: options.derivedKeyLength || DEFAULT_DERIVATION_KEY_LENGTH,
    }
}

function getWallet(wallets: Wallets, walletId: string): Wallet {
  if (!walletId) {
    throw new Error('Wallet ID not provided')
  }

  const wallet: ?Wallet = wallets.find(({ id }: Wallet): boolean => (walletId === id))

  if (!wallet) {
    throw new Error(`Wallet with id ${walletId} not found`)
  }

  return Object.assign({}, wallet)
}

function createWallet(wallets: Wallets, walletNewData: WalletNewData, password?: string): Wallets {
  const {
    scryptParams,
    passwordConfig,
    data,
    name,
    derivationPath,
    encryptionType,
    saltBytesCount,
    derivedKeyLength,
    paddedMnemonicLength,
  } = walletNewData

  if (password) {
    _testPassword(password, passwordConfig)
  }

  if (name) {
    _checkWalletUniqueness(wallets, name, 'name')
  }

  const id: string = uuidv4()

  const walletData: WalletData = {
    id,
    data,
    name: name || id,
    scryptParams: scryptParams || DEFAULT_SCRYPT_PARAMS,
    saltBytesCount: saltBytesCount || DEFAULT_SALT_BYTES_COUNT,
    derivationPath: derivationPath || DEFAULT_DERIVATION_PATH,
    encryptionType: encryptionType || DEFAULT_ENCRYPTION_TYPE,
    derivedKeyLength: derivedKeyLength || DEFAULT_DERIVATION_KEY_LENGTH,
    paddedMnemonicLength: paddedMnemonicLength || PADDED_MNEMONIC_LENGTH,
  }

  if (checkMnemonicValid(data)) {
    return _createMnemonicWallet(wallets, walletData, password)
  } else if (checkBip32XPublicKeyValid(data)) {
    return _createReadOnlyMnemonicWallet(wallets, walletData)
  } else if (checkPrivateKeyValid(data)) {
    return _createAddressWallet(wallets, walletData, password)
  } else if (checkAddressValid(data)) {
    return _createReadOnlyAddressWallet(wallets, walletData)
  } else {
    throw new Error('Wallet data not provided or invalid')
  }
}

function removeWallet(wallets: Wallets, walletId: string): Wallets {
  const wallet: Wallet = getWallet(wallets, walletId)

  return wallets.filter(({ id }: Wallet): boolean => (wallet.id !== id))
}

function updateWallet(
  wallets: Wallets,
  walletId: string,
  updatedData: WalletUpdatedData,
): Wallets {
  const {
    encrypted,
    scryptParams,
    name,
    salt,
    derivationPath,
    encryptionType,
    bip32XPublicKey,
    addressIndex,
    saltBytesCount,
    derivedKeyLength,
  } = updatedData

  const wallet: Wallet = getWallet(wallets, walletId)

  const newWallet: Wallet = Object.assign({}, wallet, {
    encrypted: encrypted || wallet.encrypted,
    scryptParams: scryptParams || wallet.scryptParams,
    name: name || wallet.name,
    salt: salt || wallet.salt,
    derivationPath: derivationPath || wallet.derivationPath,
    encryptionType: encryptionType || wallet.encryptionType,
    bip32XPublicKey: bip32XPublicKey || wallet.bip32XPublicKey,
    addressIndex: addressIndex || wallet.addressIndex,
    saltBytesCount: saltBytesCount || wallet.saltBytesCount,
    derivedKeyLength: derivedKeyLength || wallet.derivedKeyLength,
  })

  const newWallets: Wallets = removeWallet(wallets, walletId)

  return _appendWallet(newWallets, newWallet)
}

function setWalletName(wallets: Wallets, walletId: string, name: string): Wallets {
  const wallet: Wallet = getWallet(wallets, walletId)

  if (!name) {
    throw new Error('New wallet name should not be empty')
  } else if (wallet.name === name) {
    throw new Error('New wallet name should not be equal with the old one')
  }

  _checkWalletUniqueness(wallets, name, 'name')

  return updateWallet(wallets, walletId, { name })
}

function setAddressIndex(wallets: Wallets, walletId: string, addressIndex: number = 0): Wallets {
  const { type }: Wallet = getWallet(wallets, walletId)

  _checkMnemonicType(type)

  return updateWallet(wallets, walletId, { addressIndex })
}

function setDerivationPath(
  wallets: Wallets,
  walletId: string,
  password: string,
  newDerivationPath: string,
): Wallets {
  const {
    encrypted,
    scryptParams,
    type,
    salt,
    encryptionType,
    derivationPath,
    derivedKeyLength,
    isReadOnly,
  }: Wallet = getWallet(wallets, walletId)

  _checkMnemonicType(type)
  _checkNotReadOnly(isReadOnly)

  if (!checkDerivationPathValid(newDerivationPath)) {
    throw new Error('Invalid derivation path')
  }

  if (derivationPath && (derivationPath.toLowerCase() === newDerivationPath.toLowerCase())) {
    throw new Error('Can not set the same derivation path')
  }

  const dKey: Uint8Array = _deriveKeyFromPassword(password, salt, scryptParams, derivedKeyLength)

  if (!encrypted.mnemonic) {
    throw new Error('Data to decrypt not found')
  }

  const mnemonic: string = _decryptData(encrypted.mnemonic, dKey, encryptionType)
  const xpub: string = _getXPubFromMnemonic(mnemonic.trim(), newDerivationPath)

  _checkWalletUniqueness(wallets, xpub, 'bip32XPublicKey')

  return updateWallet(wallets, walletId, {
    bip32XPublicKey: xpub,
    derivationPath: newDerivationPath,
  })
}

function setPassword(
  wallets: Wallets,
  walletId: string,
  password: string,
  passwordNew: string,
  passwordOptions?: {
    scryptParams?: ScryptParams,
    encryptionType?: string,
    saltBytesCount?: number,
    derivedKeyLength?: number,
  } | void,
): Wallets {
  const {
    salt,
    type,
    encrypted,
    isReadOnly,
    scryptParams,
    encryptionType,
    derivedKeyLength,
  }: Wallet = getWallet(wallets, walletId)

  _checkNotReadOnly(isReadOnly)

  const options: SetPasswordOptions = _getPasswordOptions(passwordOptions)
  const dKey: Uint8Array = _deriveKeyFromPassword(password, salt, scryptParams, derivedKeyLength)

  const dKeyNew: Uint8Array = _deriveKeyFromPassword(
    passwordNew,
    options.salt,
    options.scryptParams,
    options.derivedKeyLength,
  )

  if (type === MNEMONIC_TYPE) {
    if (!encrypted.mnemonic) {
      throw new Error('Data to decrypt not found')
    }

    const mnemonicDec: string = _decryptData(encrypted.mnemonic, dKey, encryptionType)
    const mnemonicEnc: EncryptedData = _encryptData(mnemonicDec, dKeyNew, options.encryptionType)

    return updateWallet(wallets, walletId, Object.assign({}, options, {
      encrypted: Object.assign({}, encrypted, {
        mnemonic: mnemonicEnc,
        privateKey: null,
      }),
    }))
  } else {
    if (!encrypted.privateKey) {
      throw new Error('Data to decrypt not found')
    }

    const pKeyDec: string = _decryptPrivateKey(encrypted.privateKey, dKey, encryptionType)
    const pKeyEnc: EncryptedData = _encryptPrivateKey(pKeyDec, dKeyNew, options.encryptionType)

    return updateWallet(wallets, walletId, Object.assign({}, options, {
      encrypted: Object.assign({}, encrypted, {
        privateKey: pKeyEnc,
        mnemonic: null,
      }),
    }))
  }
}

function getAddress(wallets: Wallets, walletId: string): ?Address {
  const {
    type,
    address,
    bip32XPublicKey,
    addressIndex,
  }: Wallet = getWallet(wallets, walletId)

  if (type === ADDRESS_TYPE) {
    return address
  }

  const indexEnd: number = (addressIndex || 0) + 1

  return !bip32XPublicKey ? null : _generateAddresses(bip32XPublicKey, addressIndex, indexEnd)[0]
}

function getAddresses(wallets: Wallets, walletId: string, start: number, end: number): ?Addresses {
  const {
    type,
    bip32XPublicKey,
  }: Wallet = getWallet(wallets, walletId)

  _checkMnemonicType(type)

  if (!bip32XPublicKey) {
    return null
  }

  return _generateAddresses(bip32XPublicKey, start, end)
}

function getPrivateKey(wallets: Wallets, walletId: string, password: string): string {
  const wallet: Wallet = getWallet(wallets, walletId)

  const {
    encrypted,
    scryptParams,
    type,
    salt,
    encryptionType,
    derivedKeyLength,
    isReadOnly,
  } = wallet

  _checkNotReadOnly(isReadOnly)

  const dKey: Uint8Array = _deriveKeyFromPassword(password, salt, scryptParams, derivedKeyLength)

  if (type === MNEMONIC_TYPE) {
    if (!encrypted.mnemonic) {
      throw new Error('Data to decrypt not found')
    }

    const privateKey: string = _getPrivateKeyFromMnemonic(wallet, dKey)

    return utils.add0x(privateKey)
  } else {
    if (!encrypted.privateKey) {
      throw new Error('Data to decrypt not found')
    }

    const privateKey: string = _decryptPrivateKey(encrypted.privateKey, dKey, encryptionType)

    return utils.add0x(privateKey)
  }
}

function getMnemonic(wallets: Wallets, walletId: string, password: string): string {
  const {
    encrypted,
    scryptParams,
    salt,
    type,
    encryptionType,
    derivedKeyLength,
    isReadOnly,
  }: Wallet = getWallet(wallets, walletId)

  _checkMnemonicType(type)
  _checkNotReadOnly(isReadOnly)

  const dKey: Uint8Array = _deriveKeyFromPassword(password, salt, scryptParams, derivedKeyLength)

  if (!encrypted.mnemonic) {
    throw new Error('Data to decrypt not found')
  }

  const paddedMnemonic: string = _decryptData(encrypted.mnemonic, dKey, encryptionType)

  return paddedMnemonic.trim()
}

function getWalletData(
  wallets: Wallets,
  walletId: string,
  password?: string,
): WalletDecryptedData {
  const {
    encrypted,
    scryptParams,
    id,
    name,
    salt,
    type,
    address,
    customType,
    encryptionType,
    bip32XPublicKey,
    derivedKeyLength,
    isReadOnly,
  }: Wallet = getWallet(wallets, walletId)

  const walletDecryptedData: WalletDecryptedData = {
    id,
    name,
    address: 'n/a',
    mnemonic: 'n/a',
    type: customType,
    privateKey: 'n/a',
    bip32XPublicKey: 'n/a',
    readOnly: isReadOnly ? 'yes' : 'no',
  }

  if (type === MNEMONIC_TYPE) {
    if (isReadOnly) {
      return Object.assign({}, walletDecryptedData, {
        bip32XPublicKey: bip32XPublicKey || walletDecryptedData.bip32XPublicKey,
      })
    }

    if (!password) {
      throw new Error('Password not found')
    }

    const dKey: Uint8Array = _deriveKeyFromPassword(password, salt, scryptParams, derivedKeyLength)

    if (!encrypted.mnemonic) {
      throw new Error('Data to decrypt not found')
    }

    return Object.assign({}, walletDecryptedData, {
      bip32XPublicKey: bip32XPublicKey || walletDecryptedData.bip32XPublicKey,
      mnemonic: _decryptData(encrypted.mnemonic, dKey, encryptionType).trim(),
    })
  } else {
    if (isReadOnly) {
      return Object.assign({}, walletDecryptedData, {
        address: address || walletDecryptedData.address,
      })
    }

    if (!password) {
      throw new Error('Password not found')
    }

    const dKey: Uint8Array = _deriveKeyFromPassword(password, salt, scryptParams, derivedKeyLength)

    if (!encrypted.privateKey) {
      throw new Error('Data to decrypt not found')
    }

    return Object.assign({}, walletDecryptedData, {
      address: address || walletDecryptedData.address,
      privateKey: _decryptPrivateKey(encrypted.privateKey, dKey, encryptionType),
    })
  }
}

function serialize(wallets: Wallets): string {
  return JSON.stringify({
    wallets,
    version: CURRENT_VERSION,
  })
}

function deserialize(backupData: string): {
  wallets: Wallets,
  version: string,
} {
  try {
    return JSON.parse(backupData)
  } catch (err) {
    throw new Error('Failed to parse backup data')
  }
}

export default {
  serialize,
  getWallet,
  getAddress,
  deserialize,
  getMnemonic,
  setPassword,
  getAddresses,
  removeWallet,
  createWallet,
  setWalletName,
  getPrivateKey,
  getWalletData,
  setAddressIndex,
  setDerivationPath,
  // utils
  testPassword,
  generateMnemonic,
  checkAddressValid,
  checkMnemonicValid,
  checkPrivateKeyValid,
  checkDerivationPathValid,
  checkBip32XPublicKeyValid,
  checkChecksumAddressValid,
}
