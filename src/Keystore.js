const uuidv4 = require('uuid/v4')
const bitcore = require('bitcore-lib')
const Mnemonic = require('bitcore-mnemonic')
const { find, findIndex } = require('lodash')

const utils = require('./utils')
const encryption = require('./encryption')
const testPassword = require('./password')
const { generateMnemonic, isMnemonicValid, isBip32XPublicKeyValid } = require('./mnemonic')

const ADDRESS_LENGTH = 40
const PRIVATE_KEY_LENGTH = 64
const ADDRESSES_PER_ITERATION_LIMIT = 5

class Keystore {
  constructor(props = {}) {
    this.accounts = []
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
    this.version = 1
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

  static isHexStringValid(hash, hashLength) {
    return utils.isHexStringValid(hash, hashLength)
  }

  static isDerivationPathValid(derivationPath) {
    return bitcore.HDPrivateKey.isValidPath(derivationPath)
  }

  static testPassword(password, passwordConfig) {
    return testPassword(password, passwordConfig)
  }

  getAccounts() {
    return this.accounts
  }

  getAccount(findProps) {
    if (!(findProps && findProps.id)) {
      throw (new Error('Account ID not provided'))
    }

    return this._getAccount(findProps)
  }

  removeAccount(accountId) {
    const accountIndex = this._getAccountIndex(accountId)

    if (accountIndex === -1) {
      return false
    }

    this.accounts.splice(accountIndex, 1)

    return true
  }

  removeAccounts() {
    this.accounts = []
  }

  createAccount(props) {
    const { type, isReadOnly, password, accountName, ...otherProps } = props

    this._checkAccountUniqueness({ accountName }, 'name')

    const extendedAccountInfo = this._getExtendedAccountInfo(accountName)
    const accountData = { ...otherProps, ...extendedAccountInfo, password }

    this._checkPassword(password)

    let createAccountHandler

    if (type === this.mnemonicType) {
      createAccountHandler = isReadOnly
        ? this._createReadOnlyMnemonicAccount
        : this._createMnemonicAccount
    } else if (type === this.addressType) {
      createAccountHandler = isReadOnly
        ? this._createReadOnlyAddressAccount
        : this._createAddressAccount
    } else {
      throw (new Error('Type of account not provided or incorrect'))
    }

    createAccountHandler.call(this, accountData)

    return accountData.id
  }

  setAccountName(accountId, accountName) {
    const account = this.getAccount({ id: accountId })

    this._checkAccountExist(account)
    this._checkAccountUniqueness({ accountName }, 'name')

    if (!(accountName && accountName.length)) {
      throw (new Error('New account name should be not empty'))
    }

    return this._setAccount(account, { accountName })
  }

  getPrivateKey(password, accountId, addressIndex = 0) {
    const account = this.getAccount({ id: accountId })

    this._checkAccountExist(account)
    this._checkReadOnly(account)
    this._checkPassword(password)

    const { type, encrypted } = account

    const privateKey = (type === 'address')
      ? this._decryptData(encrypted.privateKey, password, true)
      : this._getPrivateKeyFromMnemonic(password, account, addressIndex)

    return utils.add0x(privateKey)
  }

  setAddressIndex(accountId, addressIndex = 0) {
    const account = this.getAccount({ id: accountId, type: this.mnemonicType })

    this._checkAccountExist(account)

    return this._setAccount(account, { addressIndex })
  }

  setDerivationPath(password, accountId, newDerivationPath) {
    const account = this.getAccount({ id: accountId, type: this.mnemonicType })

    this._checkAccountExist(account)
    this._checkReadOnly(account)
    this._checkPassword(password)

    if (!this.constructor.isDerivationPathValid(newDerivationPath)) {
      throw (new Error('Invalid derivation path'))
    }

    const { encrypted, derivationPath } = account

    if (newDerivationPath === derivationPath) {
      throw (new Error('Can not set the same derivation path'))
    }

    const xpub = this._getXPubFromMnemonic(password, encrypted.mnemonic, newDerivationPath)

    this._checkAccountUniqueness({ bip32XPublicKey: xpub }, 'xpub')

    return this._setAccount(account, {
      derivationPath: newDerivationPath,
      bip32XPublicKey: xpub,
    })
  }

  getAddressesFromMnemonic(accountId, iteration = 0, limit = ADDRESSES_PER_ITERATION_LIMIT) {
    const account = this.getAccount({ id: accountId, type: this.mnemonicType })

    this._checkAccountExist(account)

    return this._generateAddresses(account.bip32XPublicKey, iteration, limit)
  }

  getMnemonic(password, accountId) {
    const account = this.getAccount({ id: accountId, type: this.mnemonicType })

    this._checkAccountExist(account)
    this._checkReadOnly(account)
    this._checkPassword(password)

    const paddedMnemonic = this._decryptData(account.encrypted.mnemonic, password)

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
      throw (new Error('Failed to parse backup data'))
    }

    this._restoreBackupData(data)

    return data
  }

  getDecryptedAccounts(password) {
    this._checkPassword(password)

    return this.accounts.map((account) => {
      const { isReadOnly, type, accountName, address, encrypted } = account
      const { privateKey, mnemonic } = encrypted

      const decryptedPrivateKey = privateKey ? this._decryptData(privateKey, password) : null
      const decryptedMnemonic = mnemonic ? this._decryptData(mnemonic, password) : null

      return {
        accountName,
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

  _createMnemonicAccount(props) {
    const { id, password, accountName } = props
    const mnemonic = props.mnemonic.toLowerCase()
    const derivationPath = props.derivationPath || this.defaultDerivationPath

    if (!isMnemonicValid(mnemonic)) {
      throw (new Error('Invalid mnemonic'))
    } else if (!this.constructor.isDerivationPathValid(derivationPath)) {
      throw (new Error('Invalid derivation path'))
    }

    const paddedMnemonic = utils.leftPadString(mnemonic, ' ', this.paddedMnemonicLength)
    const encryptedMnemonic = this._encryptData(paddedMnemonic, password)
    const bip32XPublicKey = this._getXPubFromMnemonic(password, encryptedMnemonic, derivationPath)

    this._checkAccountUniqueness({ bip32XPublicKey }, 'xpub')

    this.accounts.push({
      type: this.mnemonicType,
      id,
      accountName,
      derivationPath,
      bip32XPublicKey,
      isReadOnly: false,
      addressIndex: 0,
      encrypted: {
        mnemonic: encryptedMnemonic,
      },
    })
  }

  _createReadOnlyMnemonicAccount(props) {
    const { id, bip32XPublicKey, accountName } = props

    if (!isBip32XPublicKeyValid(bip32XPublicKey)) {
      throw (new Error('Invalid bip32XPublicKey'))
    }

    this._checkAccountUniqueness({ bip32XPublicKey }, 'xpub')

    this.accounts.push({
      type: this.mnemonicType,
      id,
      accountName,
      bip32XPublicKey,
      isReadOnly: true,
      addressIndex: 0,
      encrypted: {},
    })
  }

  _createAddressAccount(props) {
    const { id, password, accountName } = props
    const privateKey = props.privateKey.toLowerCase()

    if (!utils.isHexStringValid(privateKey, PRIVATE_KEY_LENGTH)) {
      throw (new Error('Private Key is invalid'))
    }

    const address = utils.getAddressFromPrivateKey(privateKey)

    this._checkAccountUniqueness({ address }, 'address')

    this.accounts.push({
      type: this.addressType,
      id,
      address,
      accountName,
      isReadOnly: false,
      encrypted: {
        privateKey: this._encryptData(privateKey, password, true),
      },
    })
  }

  _createReadOnlyAddressAccount(props) {
    const { id, accountName } = props
    const address = props.address.toLowerCase()

    if (!utils.isHexStringValid(address, ADDRESS_LENGTH)) {
      throw (new Error('Address is invalid'))
    }

    this._checkAccountUniqueness({ address }, 'address')

    this.accounts.push({
      type: this.addressType,
      id,
      address,
      accountName,
      isReadOnly: true,
      encrypted: {},
    })
  }

  _getExtendedAccountInfo(accountName) {
    const id = uuidv4()

    return { id: uuidv4(), accountName: accountName || id }
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

  _getPrivateKeyFromMnemonic(password, account, addressIndex) {
    const { encrypted, derivationPath } = account
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

  _setAccount(account, props) {
    const accountIndex = this._getAccountIndex(account.id)

    if (accountIndex === -1) {
      throw (new Error('Account not found'))
    }

    const newAccount = { ...account, ...props }

    this.accounts.splice(accountIndex, 1, newAccount)

    return newAccount
  }

  _getAccount(findProps) {
    return find(this.accounts, findProps)
  }

  _getAccountIndex(accountId) {
    return findIndex(this.accounts, { id: accountId })
  }

  _getBackupData() {
    const {
      accounts,
      defaultDerivationPath,
      defaultEncryptionType,
      scryptParams,
      derivedKeyLength,
      checkPasswordData,
      salt,
      version,
    } = this

    return {
      accounts,
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
    if (backupData.version === 1) {
      const {
        accounts,
        defaultDerivationPath,
        defaultEncryptionType,
        scryptParams,
        derivedKeyLength,
        checkPasswordData,
        salt,
      } = backupData

      this.accounts = accounts || []
      this.defaultDerivationPath = defaultDerivationPath || this.defaultDerivationPath
      this.defaultEncryptionType = defaultEncryptionType || this.defaultEncryptionType
      this.scryptParams = scryptParams || this.scryptParams
      this.derivedKeyLength = derivedKeyLength || this.derivedKeyLength
      this.checkPasswordData = checkPasswordData || this.checkPasswordData
      this.salt = salt || this.salt
      this.version = 1
    }
  }

  _checkAccountExist(account) {
    if (!account) {
      throw (new Error('Account not found'))
    }
  }

  _checkReadOnly(account) {
    if (account.isReadOnly) {
      throw (new Error('Account is read only'))
    }
  }

  _checkPassword(password) {
    if (!(password && password.length)) {
      throw (new Error('Password is empty'))
    }

    if (!this.checkPasswordData) {
      this._setPasswordDataToCheck(password)

      return
    }

    const errMessage = 'Password is incorrect'

    try {
      const decryptedData = this._decryptData(this.checkPasswordData, password)

      if (!(decryptedData && decryptedData.length)) {
        throw (new Error(errMessage))
      }
    } catch (e) {
      throw (new Error(errMessage))
    }
  }

  _checkAccountUniqueness(uniqueProperty, propertyName) {
    const isAccountExist = !!this._getAccount(uniqueProperty)

    if (isAccountExist) {
      throw (new Error(`Account with this ${propertyName} already exists`))
    }
  }

  _setPasswordDataToCheck(password) {
    const testPasswordResult = testPassword(password, this.passwordConfig)

    if (testPasswordResult.failedTests.length) {
      throw (new Error('Password is too weak'))
    }

    const checkPasswordData = utils.generateSalt(this.saltByteCount)

    this.checkPasswordData = this._encryptData(checkPasswordData, password)
  }

  _reEncryptData(password, newPassword) {
    this.accounts.forEach((account) => {
      const { isReadOnly, encrypted } = account

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

      this._setAccount(account, { encrypted: newEncrypted })
    })
  }
}

module.exports = Keystore
