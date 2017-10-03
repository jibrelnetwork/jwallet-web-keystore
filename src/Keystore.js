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

class Keystore {
  constructor(props = {}) {
    this.accounts = props.accounts || []
    this.defaultDerivationPath = props.defaultDerivationPath || "m/44'/60'/0'/0"
    this.defaultEncryptionType = props.defaultEncryptionType || 'nacl.secretbox'
    this.addressesCountToGenerate = props.addressesCountToGenerate || 3
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

  static isMnemonicValid(mnemonic) {
    return isMnemonicValid(mnemonic)
  }

  static generateMnemonic(entropy, randomBufferLength = 32) {
    return generateMnemonic(entropy, randomBufferLength)
  }

  static isHashStringValid(hash, hashLength) {
    return utils.isHashStringValid(hash, hashLength)
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

    return find(this.accounts, findProps)
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

  setAccountName(accountId, newName) {
    const account = this.getAccount({ id: accountId })

    this._checkAccountExist(account)

    if (!(newName && newName.length)) {
      throw (new Error('New account name should be not empty'))
    }

    return this._setAccount(account, { accountName: newName })
  }

  getPrivateKey(password, accountId) {
    const account = this.getAccount({ id: accountId })

    this._checkAccountExist(account)
    this._checkReadOnly(account)
    this._checkPassword(password)

    const { encrypted } = account
    const dataToDecrypt = encrypted.privateKey

    if (!dataToDecrypt) {
      throw (new Error('Address is not setted yet'))
    }

    const decryptedData = this._decryptData(dataToDecrypt, password, true)

    return utils.add0x(decryptedData)
  }

  setAddress(password, accountId, addressIndex = 0) {
    const account = this.getAccount({ id: accountId, type: this.mnemonicType })

    this._checkAccountExist(account)

    if (!account.isReadOnly) {
      this._checkPassword(password)
    }

    const { encrypted, isReadOnly } = account
    const hdRoot = this._getHdRoot(password, account)
    const generatedKey = this._generateKey(hdRoot, addressIndex)

    if (isReadOnly) {
      return this._setAccount(account, {
        address: utils.getAddressFromPublicKey(generatedKey.publicKey.toString()),
      })
    }

    const privateKey = generatedKey.privateKey.toString()

    return this._setAccount(account, {
      address: utils.getAddressFromPrivateKey(privateKey),
      encrypted: {
        ...encrypted,
        privateKey: this._encryptData(privateKey, password, true),
      },
    })
  }

  setDerivationPath(password, accountId, newDerivationPath) {
    const account = this.getAccount({ id: accountId, type: this.mnemonicType })

    this._checkAccountExist(account)
    this._checkReadOnly(account)
    this._checkPassword(password)

    if (!(newDerivationPath && newDerivationPath.length)) {
      throw (new Error('New derivation path should be not empty'))
    }

    const { encrypted } = account
    const mnemonic = this._decryptData(encrypted.mnemonic, password)
    const hdPath = this._getHdPath(mnemonic, newDerivationPath)

    return this._setAccount(account, {
      derivationPath: newDerivationPath,
      encrypted: {
        ...encrypted,
        hdPath: this._encryptData(hdPath, password),
      },
    })
  }

  getAddressesFromMnemonic(password, accountId, iteration) {
    const account = this.getAccount({ id: accountId, type: this.mnemonicType })

    this._checkAccountExist(account)

    if (!account.isReadOnly) {
      this._checkPassword(password)
    }

    return this._generateAddresses(password, account, iteration)
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

  setPassword(password, newPassword) {
    this._checkPassword(password)
    this._setPasswordDataToCheck(newPassword)
    this._reEncryptData(password, newPassword)
  }

  _createMnemonicAccount(props) {
    const { id, password, mnemonic, accountName } = props
    const derivationPath = props.derivationPath || this.defaultDerivationPath

    if (!isMnemonicValid(mnemonic)) {
      throw (new Error('Invalid mnemonic'))
    }

    const hdPath = this._getHdPath(mnemonic, derivationPath)
    const paddedMnemonic = utils.leftPadString(mnemonic, ' ', this.paddedMnemonicLength)

    this.accounts.push({
      type: this.mnemonicType,
      id,
      accountName,
      derivationPath,
      isReadOnly: false,
      address: null,
      encrypted: {
        privateKey: null,
        mnemonic: this._encryptData(paddedMnemonic, password),
        hdPath: this._encryptData(hdPath, password),
      },
    })
  }

  _createReadOnlyMnemonicAccount(props) {
    const { id, bip32XPublicKey, accountName } = props

    if (!isBip32XPublicKeyValid(bip32XPublicKey)) {
      throw (new Error('Invalid bip32XPublicKey'))
    }

    this.accounts.push({
      type: this.mnemonicType,
      id,
      accountName,
      bip32XPublicKey,
      isReadOnly: true,
      address: null,
      encrypted: {},
    })
  }

  _createAddressAccount(props) {
    const { id, password, privateKey, accountName } = props

    if (!utils.isHashStringValid(privateKey, PRIVATE_KEY_LENGTH)) {
      throw (new Error('Private Key is invalid'))
    }

    const address = utils.getAddressFromPrivateKey(privateKey)

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
    const { id, address, accountName } = props

    if (!utils.isHashStringValid(address, ADDRESS_LENGTH)) {
      throw (new Error('Address is invalid'))
    }

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
    return {
      id: uuidv4(),
      accountName: accountName || `Account ${this.accounts.length + 1}`,
    }
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

  _generateAddresses(password, account, iteration = 0) {
    const keyIndexStart = iteration * this.addressesCountToGenerate
    const keyIndexEnd = keyIndexStart + this.addressesCountToGenerate

    const addresses = []

    const hdRoot = this._getHdRoot(password, account)

    for (let index = keyIndexStart; index < keyIndexEnd; index += 1) {
      const key = this._generateKey(hdRoot, index)

      const address = account.isReadOnly
        ? utils.getAddressFromPublicKey(key.publicKey.toString())
        : utils.getAddressFromPrivateKey(key.privateKey.toString())

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

  _getHdRoot(password, account) {
    const { bip32XPublicKey, encrypted, isReadOnly } = account

    return isReadOnly
      ? new bitcore.HDPublicKey(bip32XPublicKey)
      : new bitcore.HDPrivateKey(this._decryptData(encrypted.hdPath, password))
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

  _setPasswordDataToCheck(password) {
    const testPasswordResult = testPassword(password, this.passwordConfig)

    if (testPasswordResult.failedTests) {
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
