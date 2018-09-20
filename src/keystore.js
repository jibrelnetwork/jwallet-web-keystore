// @flow

import uuidv4 from 'uuid/v4'
import bitcore from 'bitcore-lib'
import Mnemonic from 'bitcore-mnemonic'

import { testPassword } from './password'
import { generateMnemonic, checkMnemonicValid, checkBip32XPublicKeyValid } from './mnemonic'
import * as utils from './utils'
import * as encryption from './encryption'

import packageData from '../package.json'

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

type PasswordOptionsUser = {|
  scryptParams?: ScryptParams,
  encryptionType?: string,
  saltBytesCount?: number,
  derivedKeyLength?: number,
|}

type MnemonicOptionsUser = {|
  network?: ?Network,
  passphrase?: ?string,
  derivationPath?: string,
  paddedMnemonicLength?: number,
|}

const DEFAULT_SCRYPT_PARAMS: ScryptParams = {
  N: 2 ** 18,
  r: 8,
  p: 1,
}

const DEFAULT_NETWORK: string = 'livenet'
const ADDRESS_TYPE: 'address' = 'address'
const MNEMONIC_TYPE: 'mnemonic' = 'mnemonic'
const CURRENT_VERSION: string = packageData.version
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

function _getPasswordOptions(options: ?PasswordOptionsUser): PasswordOptions {
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

function _getXPubFromMnemonic(mnemonic: string, mnemonicOptions: MnemonicOptions): string {
  const hdRoot: HDPrivateKey = _getPrivateHdRoot(mnemonic, mnemonicOptions)

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
    passwordOptions,
    mnemonicOptions,
  } = walletData

  if (!password) {
    throw new Error('Password required')
  }

  const mnemonic: string = data.toLowerCase()

  const {
    derivationPath,
    paddedMnemonicLength,
  } = mnemonicOptions

  if (!checkDerivationPathValid(derivationPath)) {
    throw new Error('Invalid derivation path')
  }

  const xpub: string = _getXPubFromMnemonic(mnemonic, mnemonicOptions)

  _checkWalletUniqueness(wallets, xpub, 'bip32XPublicKey')

  const {
    salt,
    scryptParams,
    encryptionType,
    derivedKeyLength,
  } = passwordOptions

  const dKey: Uint8Array = _deriveKeyFromPassword(password, salt, scryptParams, derivedKeyLength)
  const mnemonicPad: string = utils.leftPadString(mnemonic, ' ', paddedMnemonicLength)
  const mnemonicEnc: EncryptedData = _encryptData(mnemonicPad, dKey, encryptionType)

  return _appendWallet(wallets, {
    id,
    name,
    passwordOptions,
    mnemonicOptions,
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
    address: null,
    passwordOptions: null,
    mnemonicOptions: null,
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
    passwordOptions,
  } = walletData

  if (!password) {
    throw new Error('Password required')
  }

  const address: string = utils.getAddressFromPrivateKey(data)

  _checkWalletUniqueness(wallets, address, 'address')

  const {
    salt,
    scryptParams,
    encryptionType,
    derivedKeyLength,
  } = passwordOptions

  const dKey: Uint8Array = _deriveKeyFromPassword(password, salt, scryptParams, derivedKeyLength)

  return _appendWallet(wallets, {
    id,
    name,
    address,
    passwordOptions,
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
    mnemonicOptions: null,
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
    addressIndex: null,
    bip32XPublicKey: null,
    passwordOptions: null,
    mnemonicOptions: null,
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

function _getPrivateKeyFromMnemonic(wallet: Wallet, dKey: Uint8Array): string {
  const {
    encrypted,
    addressIndex,
    passwordOptions,
    mnemonicOptions,
  }: Wallet = wallet

  if (!(encrypted.mnemonic && passwordOptions && mnemonicOptions)) {
    throw new Error('Invalid wallet')
  }

  const mnemonic: string = _decryptData(encrypted.mnemonic, dKey, passwordOptions.encryptionType)
  const hdRoot: HDPrivateKey = _getPrivateHdRoot(mnemonic.trim(), mnemonicOptions)
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

function _testPassword(password: string): void {
  const testPasswordResult: PasswordResult = testPassword(password)

  if (testPasswordResult.score < 3) {
    throw new Error(testPasswordResult.feedback.warning)
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

  return { ...wallet }
}

function createWallet(wallets: Wallets, walletNewData: WalletNewData, password?: string): Wallets {
  const {
    scryptParams,
    data,
    name,
    network,
    passphrase,
    derivationPath,
    encryptionType,
    saltBytesCount,
    derivedKeyLength,
    paddedMnemonicLength,
  } = walletNewData

  if (password) {
    _testPassword(password)
  }

  if (name) {
    _checkWalletUniqueness(wallets, name, 'name')
  }

  const id: string = uuidv4()

  const passwordOptions: PasswordOptions = _getPasswordOptions({
    scryptParams,
    saltBytesCount,
    encryptionType,
    derivedKeyLength,
  })

  const mnemonicOptions: MnemonicOptions = _getMnemonicOptions({
    network,
    passphrase,
    derivationPath,
    paddedMnemonicLength,
  })

  const walletData: WalletData = {
    id,
    data,
    passwordOptions,
    mnemonicOptions,
    name: name || id,
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
    passwordOptions,
    mnemonicOptions,
    name,
    customType,
    bip32XPublicKey,
    addressIndex,
    isReadOnly,
  } = updatedData

  const wallet: Wallet = getWallet(wallets, walletId)

  const newWallet: Wallet = {
    ...wallet,
    encrypted: encrypted || wallet.encrypted,
    passwordOptions: passwordOptions || wallet.passwordOptions,
    mnemonicOptions: mnemonicOptions || wallet.mnemonicOptions,
    name: name || wallet.name,
    customType: customType || wallet.customType,
    bip32XPublicKey: bip32XPublicKey || wallet.bip32XPublicKey,
    addressIndex: addressIndex || wallet.addressIndex,
    isReadOnly: (typeof (isReadOnly) === 'boolean') ? isReadOnly : wallet.isReadOnly,
  }

  const newWallets: Wallets = removeWallet(wallets, walletId)

  return _appendWallet(newWallets, newWallet)
}

function addMnemonic(
  wallets: Wallets,
  walletId: string,
  mnemonicUser: string,
  password: string,
  passwordOptionsUser?: ?PasswordOptionsUser,
  mnemonicOptionsUser?: ?MnemonicOptionsUser,
): Wallets {
  _testPassword(password)

  const {
    type,
    bip32XPublicKey,
    isReadOnly,
  }: Wallet = getWallet(wallets, walletId)

  if ((type !== MNEMONIC_TYPE) || !isReadOnly || !bip32XPublicKey) {
    throw new Error('Invalid wallet type')
  }

  const mnemonic: string = mnemonicUser.toLowerCase()
  const mnemonicOptions: MnemonicOptions = _getMnemonicOptions(mnemonicOptionsUser)

  const {
    derivationPath,
    paddedMnemonicLength,
  }: MnemonicOptions = mnemonicOptions

  if (!checkDerivationPathValid(derivationPath)) {
    throw new Error('Invalid derivation path')
  }

  const xpubFromMnemonic: string = _getXPubFromMnemonic(mnemonic, mnemonicOptions)

  if (bip32XPublicKey.toLowerCase() !== xpubFromMnemonic.toLowerCase()) {
    throw new Error('This private key is not pair with existed address')
  }

  const passwordOptions: PasswordOptions = _getPasswordOptions(passwordOptionsUser)

  const {
    salt,
    scryptParams,
    encryptionType,
    derivedKeyLength,
  }: PasswordOptions = passwordOptions

  const dKey: Uint8Array = _deriveKeyFromPassword(password, salt, scryptParams, derivedKeyLength)
  const mnemonicPad: string = utils.leftPadString(mnemonic, ' ', paddedMnemonicLength)

  return updateWallet(wallets, walletId, {
    passwordOptions,
    mnemonicOptions,
    encrypted: {
      mnemonic: _encryptData(mnemonicPad, dKey, encryptionType),
      privateKey: null,
    },
    customType: 'mnemonic',
    isReadOnly: false,
  })
}

function addPrivateKey(
  wallets: Wallets,
  walletId: string,
  privateKey: string,
  password: string,
  passwordOptionsUser?: ?PasswordOptionsUser,
): Wallets {
  _testPassword(password)

  const {
    type,
    address,
    isReadOnly,
  }: Wallet = getWallet(wallets, walletId)

  if ((type !== ADDRESS_TYPE) || !isReadOnly || !address) {
    throw new Error('Invalid wallet type')
  }

  const addressFromPrivateKey: string = utils.getAddressFromPrivateKey(privateKey)

  if (address.toLowerCase() !== addressFromPrivateKey.toLowerCase()) {
    throw new Error('This private key is not pair with existed address')
  }

  const passwordOptions: PasswordOptions = _getPasswordOptions(passwordOptionsUser)

  const {
    salt,
    scryptParams,
    encryptionType,
    derivedKeyLength,
  }: PasswordOptions = passwordOptions

  const dKey: Uint8Array = _deriveKeyFromPassword(password, salt, scryptParams, derivedKeyLength)

  return updateWallet(wallets, walletId, {
    passwordOptions,
    encrypted: {
      privateKey: _encryptPrivateKey(privateKey, dKey, encryptionType),
      mnemonic: null,
    },
    customType: 'privateKey',
    isReadOnly: false,
  })
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
    passwordOptions,
    mnemonicOptions,
    type,
    isReadOnly,
  }: Wallet = getWallet(wallets, walletId)

  _checkMnemonicType(type)
  _checkNotReadOnly(isReadOnly)

  if (!checkDerivationPathValid(newDerivationPath)) {
    throw new Error('Invalid derivation path')
  }

  if (!(passwordOptions && mnemonicOptions)) {
    throw new Error('Invalid wallet')
  }

  const { derivationPath }: MnemonicOptions = mnemonicOptions

  if (derivationPath && (derivationPath.toLowerCase() === newDerivationPath.toLowerCase())) {
    throw new Error('Can not set the same derivation path')
  }

  const {
    salt,
    scryptParams,
    encryptionType,
    derivedKeyLength,
  }: PasswordOptions = passwordOptions

  const dKey: Uint8Array = _deriveKeyFromPassword(password, salt, scryptParams, derivedKeyLength)

  if (!encrypted.mnemonic) {
    throw new Error('Data to decrypt not found')
  }

  const mnemonic: string = _decryptData(encrypted.mnemonic, dKey, encryptionType)

  const mnemonicOptionsNew: MnemonicOptions = {
    ...mnemonicOptions,
    derivationPath: newDerivationPath,
  }

  const xpub: string = _getXPubFromMnemonic(mnemonic.trim(), mnemonicOptionsNew)

  _checkWalletUniqueness(wallets, xpub, 'bip32XPublicKey')

  return updateWallet(wallets, walletId, {
    bip32XPublicKey: xpub,
    mnemonicOptions: mnemonicOptionsNew,
  })
}

function setMnemonicPassphrase(
  wallets: Wallets,
  walletId: string,
  password: string,
  newPassphrase: string,
): Wallets {
  const {
    encrypted,
    passwordOptions,
    mnemonicOptions,
    type,
    isReadOnly,
  }: Wallet = getWallet(wallets, walletId)

  _checkMnemonicType(type)
  _checkNotReadOnly(isReadOnly)

  if (!(newPassphrase && passwordOptions && mnemonicOptions)) {
    throw new Error('Invalid wallet')
  }

  const { passphrase }: MnemonicOptions = mnemonicOptions

  if (passphrase && (passphrase.toLowerCase() === newPassphrase.toLowerCase())) {
    throw new Error('Can not set the same passphrase')
  }

  const {
    salt,
    scryptParams,
    encryptionType,
    derivedKeyLength,
  }: PasswordOptions = passwordOptions

  const dKey: Uint8Array = _deriveKeyFromPassword(password, salt, scryptParams, derivedKeyLength)

  if (!encrypted.mnemonic) {
    throw new Error('Data to decrypt not found')
  }

  const mnemonic: string = _decryptData(encrypted.mnemonic, dKey, encryptionType)

  const mnemonicOptionsNew: MnemonicOptions = {
    ...mnemonicOptions,
    passphrase: newPassphrase,
  }

  const xpub: string = _getXPubFromMnemonic(mnemonic.trim(), mnemonicOptionsNew)

  _checkWalletUniqueness(wallets, xpub, 'bip32XPublicKey')

  return updateWallet(wallets, walletId, {
    bip32XPublicKey: xpub,
    mnemonicOptions: mnemonicOptionsNew,
  })
}

function setPassword(
  wallets: Wallets,
  walletId: string,
  password: string,
  passwordNew: string,
  passwordOptionsUser?: ?PasswordOptionsUser,
): Wallets {
  const {
    type,
    encrypted,
    isReadOnly,
    passwordOptions,
  }: Wallet = getWallet(wallets, walletId)

  _checkNotReadOnly(isReadOnly)

  if (!passwordOptions) {
    throw new Error('Invalid wallet')
  }

  const passwordOptionsNew: PasswordOptions = _getPasswordOptions(passwordOptionsUser)

  const derivedKey: Uint8Array = _deriveKeyFromPassword(
    password,
    passwordOptions.salt,
    passwordOptions.scryptParams,
    passwordOptions.derivedKeyLength,
  )

  const derivedKeyNew: Uint8Array = _deriveKeyFromPassword(
    passwordNew,
    passwordOptionsNew.salt,
    passwordOptionsNew.scryptParams,
    passwordOptionsNew.derivedKeyLength,
  )

  if (type === MNEMONIC_TYPE) {
    if (!encrypted.mnemonic) {
      throw new Error('Data to decrypt not found')
    }

    const mnemonicDec: string = _decryptData(
      encrypted.mnemonic,
      derivedKey,
      passwordOptions.encryptionType,
    )

    const mnemonicEnc: EncryptedData = _encryptData(
      mnemonicDec,
      derivedKeyNew,
      passwordOptionsNew.encryptionType,
    )

    return updateWallet(wallets, walletId, {
      passwordOptions: passwordOptionsNew,
      encrypted: {
        mnemonic: mnemonicEnc,
        privateKey: null,
      },
    })
  } else {
    if (!encrypted.privateKey) {
      throw new Error('Data to decrypt not found')
    }

    const privateKeyDec: string = _decryptPrivateKey(
      encrypted.privateKey,
      derivedKey,
      passwordOptions.encryptionType,
    )

    const privateKeyEnc: EncryptedData = _encryptPrivateKey(
      privateKeyDec,
      derivedKeyNew,
      passwordOptionsNew.encryptionType,
    )

    return updateWallet(wallets, walletId, {
      passwordOptions: passwordOptionsNew,
      encrypted: {
        privateKey: privateKeyEnc,
        mnemonic: null,
      },
    })
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
    passwordOptions,
    type,
    isReadOnly,
  } = wallet

  _checkNotReadOnly(isReadOnly)

  if (!passwordOptions) {
    throw new Error('Invalid wallet')
  }

  const {
    salt,
    scryptParams,
    encryptionType,
    derivedKeyLength,
  }: PasswordOptions = passwordOptions

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
    passwordOptions,
    type,
    isReadOnly,
  }: Wallet = getWallet(wallets, walletId)

  _checkMnemonicType(type)
  _checkNotReadOnly(isReadOnly)

  if (!passwordOptions) {
    throw new Error('Invalid wallet')
  }

  const {
    salt,
    scryptParams,
    encryptionType,
    derivedKeyLength,
  }: PasswordOptions = passwordOptions

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
    passwordOptions,
    id,
    name,
    type,
    address,
    customType,
    bip32XPublicKey,
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
      return {
        ...walletDecryptedData,
        bip32XPublicKey: bip32XPublicKey || walletDecryptedData.bip32XPublicKey,
      }
    }

    if (!(password && passwordOptions)) {
      throw new Error('Invalid wallet')
    }

    const {
      salt,
      scryptParams,
      encryptionType,
      derivedKeyLength,
    }: PasswordOptions = passwordOptions

    const dKey: Uint8Array = _deriveKeyFromPassword(password, salt, scryptParams, derivedKeyLength)

    if (!encrypted.mnemonic) {
      throw new Error('Data to decrypt not found')
    }

    return {
      ...walletDecryptedData,
      bip32XPublicKey: bip32XPublicKey || walletDecryptedData.bip32XPublicKey,
      mnemonic: _decryptData(encrypted.mnemonic, dKey, encryptionType).trim(),
    }
  } else {
    if (isReadOnly) {
      return {
        ...walletDecryptedData,
        address: address || walletDecryptedData.address,
      }
    }

    if (!(password && passwordOptions)) {
      throw new Error('Invalid wallet')
    }

    const {
      salt,
      scryptParams,
      encryptionType,
      derivedKeyLength,
    }: PasswordOptions = passwordOptions

    const dKey: Uint8Array = _deriveKeyFromPassword(password, salt, scryptParams, derivedKeyLength)

    if (!encrypted.privateKey) {
      throw new Error('Data to decrypt not found')
    }

    return {
      ...walletDecryptedData,
      address: address || walletDecryptedData.address,
      privateKey: _decryptPrivateKey(encrypted.privateKey, dKey, encryptionType),
    }
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
  addMnemonic,
  getAddresses,
  removeWallet,
  createWallet,
  addPrivateKey,
  setWalletName,
  getPrivateKey,
  getWalletData,
  setAddressIndex,
  setDerivationPath,
  setMnemonicPassphrase,
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
