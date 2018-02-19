const uuidv4 = require('uuid/v4')
const bitcore = require('bitcore-lib')
const Mnemonic = require('bitcore-mnemonic')
const { clone } = require('ramda')
const { find, findIndex } = require('lodash')

const utils = require('./utils')
const encryption = require('./encryption')
const testPassword = require('./password')
const { generateMnemonic, isMnemonicValid, isBip32XPublicKeyValid } = require('./mnemonic')

const packageData = require('../package.json')

const ADDRESSES_PER_ITERATION_LIMIT = 5

class Keystore {
  constructor(props = {}) {
    this.wallets = []
    this.defaultDerivationPath = props.defaultDerivationPath || "m/44'/60'/0'/0"
    this.defaultEncryptionType = props.defaultEncryptionType || 'nacl.secretbox'
    this.paddedMnemonicLength = props.paddedMnemonicLength || 120
    this.saltByteCount = props.saltByteCount || 32
    this.scryptParams = props.scryptParams || { N: 2 ** 18, r: 8, p: 1 }
    this.derivedKeyLength = props.derivedKeyLength || 32
    this.passwordConfig = props.passwordConfig || {}
    this.mnemonicType = 'mnemonic'
    this.addressType = 'address'
    this.checkPasswordData = null
    this.salt = utils.generateSalt(this.saltByteCount)
    this.version = packageData.version
  }

  static generateMnemonic(entropy, randomBufferLength = 32) {
    return generateMnemonic(entropy, randomBufferLength)
  }

  static isMnemonicValid(mnemonic) {
    return isMnemonicValid(mnemonic)
  }

  static isBip32XPublicKeyValid(bip32XPublicKey) {
    return isBip32XPublicKeyValid(bip32XPublicKey)
  }

  static isValidAddress(address) {
    return utils.isValidAddress(address)
  }

  static isValidPrivateKey(privateKey) {
    return utils.isValidPrivateKey(privateKey)
  }

  static isDerivationPathValid(derivationPath) {
    return bitcore.HDPrivateKey.isValidPath(derivationPath)
  }

  static testPassword(password, passwordConfig) {
    return testPassword(password, passwordConfig)
  }

  getWallets() {
    return clone(this.wallets)
  }

  getWallet(findProps) {
    if (!(findProps && findProps.id)) {
      throw new Error('Wallet ID not provided')
    }

    return this._getWallet(findProps)
  }

  removeWallet(walletId) {
    const walletIndex = this._getWalletIndex(walletId)

    if (walletIndex === -1) {
      return false
    }

    this.wallets.splice(walletIndex, 1)

    if (!this.wallets.length) {
      this._removePasswordDataToCheck()
    }

    return true
  }

  removeWallets(password) {
    if (password) {
      this._checkPassword(password)
    }

    this.wallets = []
    this._removePasswordDataToCheck()
  }

  createWallet(props) {
    const { type, isReadOnly, password, walletName, ...otherProps } = props

    this._checkWalletUniqueness({ walletName }, 'name')

    const extendedWalletInfo = this._getExtendedWalletInfo(walletName)
    const walletData = { ...otherProps, ...extendedWalletInfo, password }

    this._checkPassword(password)

    let createWalletHandler

    if (type === this.mnemonicType) {
      createWalletHandler = isReadOnly
        ? this._createReadOnlyMnemonicWallet
        : this._createMnemonicWallet
    } else if (type === this.addressType) {
      createWalletHandler = isReadOnly
        ? this._createReadOnlyAddressWallet
        : this._createAddressWallet
    } else {
      throw new Error('Type of wallet not provided or incorrect')
    }

    createWalletHandler.call(this, walletData)

    return walletData.id
  }

  setWalletName(walletId, walletName) {
    const wallet = this.getWallet({ id: walletId })

    this._checkWalletExist(wallet)

    if (wallet.walletName === walletName) {
      return wallet
    }

    this._checkWalletUniqueness({ walletName }, 'name')

    if (!(walletName && walletName.length)) {
      throw new Error('New wallet name should be not empty')
    }

    return this._setWallet(wallet, { walletName })
  }

  getPrivateKey(password, walletId, addressIndex = 0) {
    const wallet = this.getWallet({ id: walletId })

    this._checkWalletExist(wallet)
    this._checkReadOnly(wallet)
    this._checkPassword(password)

    const { type, encrypted } = wallet

    const privateKey = (type === 'address')
      ? this._decryptData(encrypted.privateKey, password, true)
      : this._getPrivateKeyFromMnemonic(password, wallet, addressIndex)

    return utils.add0x(privateKey)
  }

  setAddressIndex(walletId, addressIndex = 0) {
    const wallet = this.getWallet({ id: walletId, type: this.mnemonicType })

    this._checkWalletExist(wallet)

    return this._setWallet(wallet, { addressIndex })
  }

  setDerivationPath(password, walletId, newDerivationPath) {
    const wallet = this.getWallet({ id: walletId, type: this.mnemonicType })

    this._checkWalletExist(wallet)
    this._checkReadOnly(wallet)
    this._checkPassword(password)

    if (!this.constructor.isDerivationPathValid(newDerivationPath)) {
      throw new Error('Invalid derivation path')
    }

    const { encrypted, derivationPath } = wallet

    if (newDerivationPath === derivationPath) {
      throw new Error('Can not set the same derivation path')
    }

    const xpub = this._getXPubFromMnemonic(password, encrypted.mnemonic, newDerivationPath)

    this._checkWalletUniqueness({ bip32XPublicKey: xpub }, 'xpub')

    return this._setWallet(wallet, {
      derivationPath: newDerivationPath,
      bip32XPublicKey: xpub,
    })
  }

  getAddressesFromMnemonic(walletId, iteration = 0, limit = ADDRESSES_PER_ITERATION_LIMIT) {
    const wallet = this.getWallet({ id: walletId, type: this.mnemonicType })

    this._checkWalletExist(wallet)

    return this._generateAddresses(wallet.bip32XPublicKey, iteration, limit)
  }

  getAddressFromMnemonic(walletId, addressIndex = 0) {
    const wallet = this.getWallet({ id: walletId, type: this.mnemonicType })

    this._checkWalletExist(wallet)

    return this._generateAddresses(wallet.bip32XPublicKey, addressIndex, 1).shift()
  }

  getMnemonic(password, walletId) {
    const wallet = this.getWallet({ id: walletId, type: this.mnemonicType })

    this._checkWalletExist(wallet)
    this._checkReadOnly(wallet)
    this._checkPassword(password)

    const paddedMnemonic = this._decryptData(wallet.encrypted.mnemonic, password)

    return paddedMnemonic.trim()
  }

  serialize() {
    return JSON.stringify(this._getBackupData())
  }

  deserialize(backupData) {
    let data

    try {
      data = JSON.parse(backupData)
    } catch (err) {
      throw new Error('Failed to parse backup data')
    }

    this._restoreBackupData(data)

    return data
  }

  getDecryptedWallets(password) {
    this._checkPassword(password)

    return this.wallets.map((wallet) => {
      const { isReadOnly, type, walletName, address, encrypted } = wallet
      const { privateKey, mnemonic } = encrypted

      const decryptedPrivateKey = privateKey ? this._decryptData(privateKey, password) : null
      const decryptedMnemonic = mnemonic ? this._decryptData(mnemonic, password) : null

      return {
        walletName,
        type,
        readOnly: isReadOnly ? 'yes' : 'no',
        address: address || 'n/a',
        privateKey: decryptedPrivateKey || 'n/a',
        mnemonic: decryptedMnemonic ? decryptedMnemonic.trim() : 'n/a',
      }
    })
  }

  setPassword(password, newPassword) {
    this._checkPassword(password)
    this._setPasswordDataToCheck(newPassword)
    this._reEncryptData(password, newPassword)
  }

  _createMnemonicWallet(props) {
    const { id, password, walletName } = props
    const mnemonic = props.mnemonic.toLowerCase()
    const derivationPath = props.derivationPath || this.defaultDerivationPath

    if (!isMnemonicValid(mnemonic)) {
      throw new Error('Invalid mnemonic')
    } else if (!this.constructor.isDerivationPathValid(derivationPath)) {
      throw new Error('Invalid derivation path')
    }

    const paddedMnemonic = utils.leftPadString(mnemonic, ' ', this.paddedMnemonicLength)
    const encryptedMnemonic = this._encryptData(paddedMnemonic, password)
    const bip32XPublicKey = this._getXPubFromMnemonic(password, encryptedMnemonic, derivationPath)

    this._checkWalletUniqueness({ bip32XPublicKey }, 'xpub')

    this.wallets.push({
      type: this.mnemonicType,
      id,
      walletName,
      derivationPath,
      bip32XPublicKey,
      isReadOnly: false,
      addressIndex: 0,
      encrypted: {
        mnemonic: encryptedMnemonic,
      },
    })
  }

  _createReadOnlyMnemonicWallet(props) {
    const { id, bip32XPublicKey, walletName } = props

    if (!isBip32XPublicKeyValid(bip32XPublicKey)) {
      throw new Error('Invalid bip32XPublicKey')
    }

    this._checkWalletUniqueness({ bip32XPublicKey }, 'xpub')

    this.wallets.push({
      type: this.mnemonicType,
      id,
      walletName,
      bip32XPublicKey,
      isReadOnly: true,
      addressIndex: 0,
      encrypted: {},
    })
  }

  _createAddressWallet(props) {
    const { id, password, walletName, privateKey } = props

    if (!utils.isValidPrivateKey(privateKey)) {
      throw new Error('Private Key is invalid')
    }

    const address = utils.getAddressFromPrivateKey(privateKey)
    const addressLowerCase = address.toLowerCase()
    this._checkWalletUniqueness({ addressLowerCase }, 'address')

    this.wallets.push({
      type: this.addressType,
      id,
      address,
      addressLowerCase,
      walletName,
      isReadOnly: false,
      encrypted: {
        privateKey: this._encryptData(privateKey, password, true),
      },
    })
  }

  _createReadOnlyAddressWallet(props) {
    const { id, walletName, address } = props

    if (!utils.isValidAddress(address)) {
      throw new Error('Address is invalid')
    }

    const addressLowerCase = address.toLowerCase()
    this._checkWalletUniqueness({ addressLowerCase }, 'address')

    this.wallets.push({
      type: this.addressType,
      id,
      address,
      addressLowerCase,
      walletName,
      isReadOnly: true,
      encrypted: {},
    })
  }

  _getExtendedWalletInfo(walletName) {
    const id = uuidv4()

    return { id: uuidv4(), walletName: walletName || id }
  }

  _deriveKeyFromPassword(password) {
    const { scryptParams, derivedKeyLength, salt } = this

    return utils.deriveKeyFromPassword(password, scryptParams, derivedKeyLength, salt)
  }

  _encryptData(dataToEncrypt, password, isPrivateKey = false) {
    return encryption.encryptData({
      isPrivateKey,
      data: dataToEncrypt,
      encryptionType: this.defaultEncryptionType,
      derivedKey: this._deriveKeyFromPassword(password),
    })
  }

  _decryptData(dataToDecrypt, password, isPrivateKey = false) {
    return encryption.decryptData({
      isPrivateKey,
      data: dataToDecrypt,
      derivedKey: this._deriveKeyFromPassword(password),
    })
  }

  _getPrivateKeyFromMnemonic(password, wallet, addressIndex) {
    const { encrypted, derivationPath } = wallet
    const hdRoot = this._getPrivateHdRoot(password, encrypted.mnemonic, derivationPath)
    const generatedKey = this._generateKey(hdRoot, addressIndex)

    return generatedKey.privateKey.toString()
  }

  _generateAddresses(bip32XPublicKey, iteration, limit) {
    const keyIndexStart = iteration * limit
    const keyIndexEnd = keyIndexStart + limit

    const addresses = []

    const hdRoot = this._getPublicHdRoot(bip32XPublicKey)

    for (let index = keyIndexStart; index < keyIndexEnd; index += 1) {
      const generatedKey = this._generateKey(hdRoot, index)
      const publicKey = generatedKey.publicKey.toString()
      const address = utils.getAddressFromPublicKey(publicKey)

      addresses.push(address)
    }

    return addresses
  }

  _generateKey(hdRoot, keyIndexToDerive) {
    return hdRoot.derive(keyIndexToDerive)
  }

  _getHdPath(mnemonic, derivationPath) {
    const hdRoot = new Mnemonic(mnemonic.trim()).toHDPrivateKey().xprivkey
    const hdRootKey = new bitcore.HDPrivateKey(hdRoot)

    return hdRootKey.derive(derivationPath).xprivkey
  }

  _getPublicHdRoot(bip32XPublicKey) {
    return new bitcore.HDPublicKey(bip32XPublicKey)
  }

  _getPrivateHdRoot(password, encryptedMnemonic, derivationPath) {
    const mnemonic = this._decryptData(encryptedMnemonic, password)
    const hdPath = this._getHdPath(mnemonic, derivationPath)

    return new bitcore.HDPrivateKey(hdPath)
  }

  _getXPubFromMnemonic(password, encryptedMnemonic, derivationPath) {
    const hdRoot = this._getPrivateHdRoot(password, encryptedMnemonic, derivationPath)

    return hdRoot.hdPublicKey.toString()
  }

  _setWallet(wallet, props) {
    const walletIndex = this._getWalletIndex(wallet.id)

    if (walletIndex === -1) {
      throw new Error('Wallet not found')
    }

    const newWallet = { ...wallet, ...props }

    this.wallets.splice(walletIndex, 1, newWallet)

    return newWallet
  }

  _getWallet(findProps) {
    return find(this.wallets, findProps)
  }

  _getWalletIndex(walletId) {
    return findIndex(this.wallets, { id: walletId })
  }

  _getBackupData() {
    const {
      wallets,
      defaultDerivationPath,
      defaultEncryptionType,
      scryptParams,
      derivedKeyLength,
      checkPasswordData,
      salt,
      version,
    } = this

    return {
      wallets,
      defaultDerivationPath,
      defaultEncryptionType,
      scryptParams,
      derivedKeyLength,
      checkPasswordData,
      salt,
      version,
    }
  }

  _restoreBackupData(backupData) {
    if (backupData.version <= packageData.version) {
      const {
        wallets,
        defaultDerivationPath,
        defaultEncryptionType,
        scryptParams,
        derivedKeyLength,
        checkPasswordData,
        salt,
      } = backupData

      this.wallets = wallets || []
      this.defaultDerivationPath = defaultDerivationPath || this.defaultDerivationPath
      this.defaultEncryptionType = defaultEncryptionType || this.defaultEncryptionType
      this.scryptParams = scryptParams || this.scryptParams
      this.derivedKeyLength = derivedKeyLength || this.derivedKeyLength
      this.checkPasswordData = checkPasswordData || this.checkPasswordData
      this.salt = salt || this.salt
      this.version = packageData.version
    }
  }

  _checkWalletExist(wallet) {
    if (!wallet) {
      throw new Error('Wallet not found')
    }
  }

  _checkReadOnly(wallet) {
    if (wallet.isReadOnly) {
      throw new Error('Wallet is read only')
    }
  }

  _checkPassword(password) {
    if (!(password && password.length)) {
      throw new Error('Password is empty')
    }

    if (!this.checkPasswordData) {
      this._setPasswordDataToCheck(password)

      return
    }

    const errMessage = 'Password is incorrect'

    try {
      const decryptedData = this._decryptData(this.checkPasswordData, password)

      if (!(decryptedData && decryptedData.length)) {
        throw new Error(errMessage)
      }
    } catch (e) {
      throw new Error(errMessage)
    }
  }

  _checkWalletUniqueness(uniqueProperty, propertyName) {
    const isWalletExist = !!this._getWallet(uniqueProperty)

    if (isWalletExist) {
      throw new Error(`Wallet with this ${propertyName} already exists`)
    }
  }

  _setPasswordDataToCheck(password) {
    const testPasswordResult = testPassword(password, this.passwordConfig)

    if (testPasswordResult.failedTests.length) {
      throw new Error(testPasswordResult.errors[0])
    }

    const checkPasswordData = utils.generateSalt(this.saltByteCount)

    this.checkPasswordData = this._encryptData(checkPasswordData, password)
  }

  _removePasswordDataToCheck() {
    this.checkPasswordData = null
  }

  _reEncryptData(password, newPassword) {
    this.wallets.forEach((wallet) => {
      const { isReadOnly, encrypted } = wallet

      if (isReadOnly) {
        return
      }

      const newEncrypted = {}

      Object.keys(encrypted).forEach((key) => {
        const encryptedItem = encrypted[key]
        const isPrivateKey = (key === 'privateKey')

        if (encryptedItem) {
          const decryptedItem = this._decryptData(encryptedItem, password, isPrivateKey)

          newEncrypted[key] = this._encryptData(decryptedItem, newPassword)
        } else {
          newEncrypted[key] = encryptedItem
        }
      })

      this._setWallet(wallet, { encrypted: newEncrypted })
    })
  }
}

module.exports = Keystore
