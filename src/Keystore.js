const R = require('ramda')
const uuidv4 = require('uuid/v4')
const bitcore = require('bitcore-lib')
const Mnemonic = require('bitcore-mnemonic')

const utils = require('./utils')
const encryption = require('./encryption')
const testPassword = require('./password')
const { generateMnemonic, isMnemonicValid, isBip32XPublicKeyValid } = require('./mnemonic')

const packageData = require('../package.json')

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
    this.addressesFromMnemonicPerIteration = 5
    this.mnemonicType = 'mnemonic'
    this.addressType = 'address'
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

  static isAddressValid(address) {
    return utils.isAddressValid(address)
  }

  static isPrivateKeyValid(privateKey) {
    return utils.isPrivateKeyValid(privateKey)
  }

  static isDerivationPathValid(derivationPath) {
    return bitcore.HDPrivateKey.isValidPath(derivationPath)
  }

  static testPassword(password, passwordConfig) {
    return testPassword(password, passwordConfig)
  }

  getWallets() {
    return R.clone(this.wallets)
  }

  getWallet(walletId) {
    if (!walletId) {
      throw new Error('Wallet ID not provided')
    }

    const wallet = R.find(R.propEq('id', walletId))(this.wallets)

    if (!wallet) {
      throw new Error(`Wallet with id ${walletId} not found`)
    }

    return R.clone(wallet)
  }

  removeWallet(walletId) {
    const wallet = this.getWallet(walletId)

    const isNotWalletId = ({ id }) => (id !== walletId)
    this.wallets = R.filter(isNotWalletId)(this.wallets)

    return wallet
  }

  removeWallets() {
    this.wallets = []
  }

  createWallet(props) {
    const { type, isReadOnly, password, name, ...otherProps } = props

    this._testPassword(password)

    const extendedInfo = this._getExtendedWalletInfo(name)
    const walletData = { ...otherProps, ...extendedInfo, password }

    this._checkWalletUniqueness(walletData.name, 'name')

    if (type === this.mnemonicType) {
      if (isReadOnly) {
        this._createReadOnlyMnemonicWallet(walletData)
      } else {
        this._createMnemonicWallet(walletData)
      }
    } else if (type === this.addressType) {
      if (isReadOnly) {
        this._createReadOnlyAddressWallet(walletData)
      } else {
        this._createAddressWallet(walletData)
      }
    } else {
      throw new Error('Type of wallet not provided or invalid')
    }

    return walletData.id
  }

  setWalletName(walletId, name) {
    const wallet = this.getWallet(walletId)

    if (!name) {
      throw new Error('New wallet name should not be empty')
    } else if (wallet.name === name) {
      throw new Error('New wallet name should not be equal with the old one')
    }

    this._checkWalletUniqueness(name, 'name')

    return this._updateWallet(walletId, { name })
  }

  getPrivateKey(password, walletId) {
    const { isReadOnly, type, salt, encrypted } = this.getWallet(walletId)

    this._isNotReadOnly(isReadOnly)

    const privateKey = (type === this.mnemonicType)
      ? this._getPrivateKeyFromMnemonic(password, walletId)
      : this._decryptPrivateKey(encrypted.privateKey, password, salt)

    return utils.add0x(privateKey)
  }

  setAddressIndex(walletId, addressIndex = 0) {
    const { type } = this.getWallet(walletId)

    this._isMnemonicType(type)

    return this._updateWallet(walletId, { addressIndex })
  }

  setDerivationPath(password, walletId, newDerivationPath) {
    const { isReadOnly, type, salt, encrypted, derivationPath } = this.getWallet(walletId)

    this._isMnemonicType(type)
    this._isNotReadOnly(isReadOnly)

    if (!this.constructor.isDerivationPathValid(newDerivationPath)) {
      throw new Error('Invalid derivation path')
    }

    if (R.equals(R.toLower(newDerivationPath), R.toLower(derivationPath))) {
      throw new Error('Can not set the same derivation path')
    }

    const xpub = this._getXPubFromMnemonic(password, salt, encrypted.mnemonic, newDerivationPath)

    this._checkWalletUniqueness(xpub, 'bip32XPublicKey')

    return this._updateWallet(walletId, {
      derivationPath: newDerivationPath,
      bip32XPublicKey: xpub,
    })
  }

  getAddressesFromMnemonic(
    walletId,
    iteration = 0,
    limit = this.addressesFromMnemonicPerIteration
  ) {
    const { type, bip32XPublicKey } = this.getWallet(walletId)

    this._isMnemonicType(type)

    return this._generateAddresses(bip32XPublicKey, iteration, limit)
  }

  getAddress(walletId) {
    const { type, address, addressIndex, bip32XPublicKey } = this.getWallet(walletId)

    return (type === this.mnemonicType)
      ? R.head(this._generateAddresses(bip32XPublicKey, addressIndex, 1))
      : address
  }

  getMnemonic(password, walletId) {
    const { isReadOnly, type, salt, encrypted } = this.getWallet(walletId)

    this._isMnemonicType(type)
    this._isNotReadOnly(isReadOnly)

    const paddedMnemonic = this._decryptData(encrypted.mnemonic, password, salt)

    return paddedMnemonic.trim()
  }

  getDecryptedWallet(password, walletId) {
    const { id, isReadOnly, type, name, address, salt, encrypted } = this.getWallet(walletId)

    const walletData = {
      id,
      name,
      type,
      readOnly: isReadOnly ? 'yes' : 'no',
    }

    if (isReadOnly) {
      return walletData
    }

    if (type === this.mnemonicType) {
      return R.assoc('mnemonic', this._decryptData(encrypted.mnemonic, password, salt))(walletData)
    }

    return R.compose(
      R.assoc('address', address),
      R.assoc('privateKey', this._decryptPrivateKey(encrypted.privateKey, password, salt))
    )(walletData)
  }

  setPassword(password, newPassword, walletId) {
    this._reEncryptData(password, newPassword, walletId)
  }

  serialize() {
    return JSON.stringify(this._getBackupData())
  }

  deserialize(backupData) {
    try {
      const data = JSON.parse(backupData)
      this._restoreBackupData(data)

      return data
    } catch (err) {
      throw new Error('Failed to parse backup data')
    }
  }

  _createMnemonicWallet(props) {
    const { id, password, name } = props
    const mnemonic = R.toLower(props.mnemonic)
    const derivationPath = props.derivationPath || this.defaultDerivationPath

    if (!isMnemonicValid(mnemonic)) {
      throw new Error('Invalid mnemonic')
    } else if (!this.constructor.isDerivationPathValid(derivationPath)) {
      throw new Error('Invalid derivation path')
    }

    const salt = utils.generateSalt(this.saltByteCount)
    const paddedMnemonic = utils.leftPadString(mnemonic, ' ', this.paddedMnemonicLength)
    const encryptedMnemonic = this._encryptData(paddedMnemonic, password, salt)
    const xpub = this._getXPubFromMnemonic(password, salt, encryptedMnemonic, derivationPath)

    this._checkWalletUniqueness(xpub, 'bip32XPublicKey')

    this._appendWallet({
      id,
      name,
      salt,
      derivationPath,
      addressIndex: 0,
      isReadOnly: false,
      bip32XPublicKey: xpub,
      customType: 'mnemonic',
      type: this.mnemonicType,
      encrypted: {
        privateKey: null,
        mnemonic: encryptedMnemonic,
      },
      /**
       * Another wallet data, necessary for consistency of types
       */
      address: null,
    })
  }

  _createReadOnlyMnemonicWallet(props) {
    const { id, bip32XPublicKey, name } = props

    if (!isBip32XPublicKeyValid(bip32XPublicKey)) {
      throw new Error('Invalid bip32XPublicKey')
    }

    this._checkWalletUniqueness(bip32XPublicKey, 'bip32XPublicKey')

    this._appendWallet({
      id,
      name,
      bip32XPublicKey,
      addressIndex: 0,
      isReadOnly: true,
      customType: 'bip32Xpub',
      type: this.mnemonicType,
      /**
       * Another wallet data, necessary for consistency of types
       */
      salt: null,
      address: null,
      encrypted: null,
      derivationPath: null,
    })
  }

  _createAddressWallet(props) {
    const { id, password, name, privateKey } = props

    if (!utils.isPrivateKeyValid(privateKey)) {
      throw new Error('Private Key is invalid')
    }

    const salt = utils.generateSalt(this.saltByteCount)
    const address = utils.getAddressFromPrivateKey(privateKey)
    this._checkWalletUniqueness(address, 'address')

    this._appendWallet({
      id,
      name,
      salt,
      address,
      isReadOnly: false,
      type: this.addressType,
      customType: 'privateKey',
      encrypted: {
        mnemonic: null,
        privateKey: this._encryptPrivateKey(privateKey, password, salt),
      },
      /**
       * Another wallet data, necessary for consistency of types
       */
      addressIndex: null,
      derivationPath: null,
      bip32XPublicKey: null,
    })
  }

  _createReadOnlyAddressWallet(props) {
    const { id, name, address } = props

    if (!utils.isAddressValid(address)) {
      throw new Error('Address is invalid')
    }

    this._checkWalletUniqueness(address, 'address')

    this._appendWallet({
      id,
      name,
      address,
      isReadOnly: true,
      customType: 'address',
      type: this.addressType,
      /**
       * Another wallet data, necessary for consistency of types
       */
      salt: null,
      encrypted: null,
      addressIndex: null,
      derivationPath: null,
      bip32XPublicKey: null,
    })
  }

  _appendWallet(wallet) {
    this.wallets = R.append(wallet)(this.wallets)
  }

  _getExtendedWalletInfo(name) {
    const id = uuidv4()

    return { id, name: name || id }
  }

  _deriveKeyFromPassword(password, salt) {
    if (!password) {
      throw new Error('Password is empty')
    }

    return utils.deriveKeyFromPassword(password, this.scryptParams, this.derivedKeyLength, salt)
  }

  _encryptPrivateKey(dataToEncrypt, password, salt) {
    return this._encryptData(dataToEncrypt, password, salt, true)
  }

  _encryptData(dataToEncrypt, password, salt, isPrivateKey = false) {
    return encryption.encryptData({
      isPrivateKey,
      data: dataToEncrypt,
      encryptionType: this.defaultEncryptionType,
      derivedKey: this._deriveKeyFromPassword(password, salt),
    })
  }

  _decryptPrivateKey(dataToDecrypt, password, salt) {
    return this._decryptData(dataToDecrypt, password, salt, true)
  }

  _decryptData(dataToDecrypt, password, salt, isPrivateKey = false) {
    return encryption.decryptData({
      isPrivateKey,
      data: dataToDecrypt,
      derivedKey: this._deriveKeyFromPassword(password, salt),
    })
  }

  _getPrivateKeyFromMnemonic(password, walletId) {
    const { encrypted, derivationPath, addressIndex, salt } = this.getWallet(walletId)
    const hdRoot = this._getPrivateHdRoot(password, salt, encrypted.mnemonic, derivationPath)
    const generatedKey = this._generateKey(hdRoot, addressIndex)

    return generatedKey.privateKey.toString()
  }

  _generateAddresses(bip32XPublicKey, iteration, limit) {
    const keyIndexStart = iteration * limit
    const keyIndexEnd = keyIndexStart + limit
    const hdRoot = this._getPublicHdRoot(bip32XPublicKey)
    const range = R.range(keyIndexStart, keyIndexEnd)

    return R.map(index => this._generateAddress(hdRoot, index))(range)
  }

  _generateAddress(hdRoot, index) {
    const generatedKey = this._generateKey(hdRoot, index)
    const publicKey = generatedKey.publicKey.toString()

    return utils.getAddressFromPublicKey(publicKey)
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

  _getPrivateHdRoot(password, salt, encryptedMnemonic, derivationPath) {
    const mnemonic = this._decryptData(encryptedMnemonic, password, salt)
    const hdPath = this._getHdPath(mnemonic, derivationPath)

    return new bitcore.HDPrivateKey(hdPath)
  }

  _getXPubFromMnemonic(password, salt, encryptedMnemonic, derivationPath) {
    const hdRoot = this._getPrivateHdRoot(password, salt, encryptedMnemonic, derivationPath)

    return hdRoot.hdPublicKey.toString()
  }

  _updateWallet(walletId, newData) {
    const wallet = this.getWallet(walletId)
    const newWallet = { ...wallet, ...newData }

    this.removeWallet(walletId)
    this._appendWallet(newWallet)

    return newWallet
  }

  _getBackupData() {
    return R.pick([
      'wallets',
      'defaultDerivationPath',
      'defaultEncryptionType',
      'scryptParams',
      'derivedKeyLength',
      'version',
    ])(this)
  }

  _restoreBackupData(backupData) {
    if (backupData.version <= packageData.version) {
      const {
        wallets,
        defaultDerivationPath,
        defaultEncryptionType,
        scryptParams,
        derivedKeyLength,
      } = backupData

      this.wallets = wallets || []
      this.defaultDerivationPath = defaultDerivationPath || this.defaultDerivationPath
      this.defaultEncryptionType = defaultEncryptionType || this.defaultEncryptionType
      this.scryptParams = scryptParams || this.scryptParams
      this.derivedKeyLength = derivedKeyLength || this.derivedKeyLength
      this.version = packageData.version
    }
  }

  _isNotReadOnly(isReadOnly) {
    if (isReadOnly) {
      throw new Error('Wallet is read only')
    }
  }

  _isMnemonicType(type) {
    if (type !== this.mnemonicType) {
      throw new Error('Wallet type is not mnemonic')
    }
  }

  _checkWalletUniqueness(uniqueProperty, propertyName) {
    const isFound = (wallet) => {
      const property = wallet[propertyName]

      return property
        ? R.equals(R.toLower(property), R.toLower(uniqueProperty))
        : false
    }

    const foundWallet = R.compose(
      R.head,
      R.filter(isFound)
    )(this.wallets)

    if (foundWallet) {
      throw new Error(`Wallet with this ${propertyName} already exists`)
    }
  }

  _testPassword(password) {
    const testPasswordResult = testPassword(password, this.passwordConfig)

    if (testPasswordResult.failedTests.length) {
      throw new Error(testPasswordResult.errors[0])
    }
  }

  _reEncryptData(password, newPassword, walletId) {
    const { isReadOnly, type, salt, encrypted } = this.getWallet(walletId)

    if (isReadOnly) {
      return
    }

    if (type === this.mnemonicType) {
      const decryptedMnemonic = this._decryptData(encrypted.mnemonic, password, salt)
      const mnemonic = this._encryptData(decryptedMnemonic, newPassword, salt)

      this._updateWallet(walletId, {
        encrypted: R.assoc('mnemonic', mnemonic)(encrypted),
      })
    } else {
      const decryptedPrivateKey = this._decryptPrivateKey(encrypted.privateKey, password, salt)
      const privateKey = this._encryptPrivateKey(decryptedPrivateKey, newPassword, salt)

      this._updateWallet(walletId, {
        encrypted: R.assoc('privateKey', privateKey)(encrypted),
      })
    }
  }
}

module.exports = Keystore
