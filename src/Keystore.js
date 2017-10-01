const uuidv4 = require('uuid/v4')
const bitcore = require('bitcore-lib')
const Mnemonic = require('bitcore-mnemonic')
const { cloneDeep, find, findIndex } = require('lodash')

const utils = require('./utils')
const encryption = require('./encryption')

const { generateMnemonic, isMnemonicValid } = require('./mnemonic')

class Keystore {
  constructor() {
    this.accounts = []
    this.defaultDerivationPath = "m/44'/0'/0'/0"
    this.defaultEncryptionType = 'nacl.secretbox'
    this.randomBufferLength = 32
    this.saltByteCount = 32
    this.mnemonicType = 'mnemonic'
    this.addressType = 'address'
    this.scryptParams = { N: 2 ** 18, r: 8, p: 1 }
    this.derivedKeyLength = 32
    this.version = 1
  }

  isMnemonicValid(mnemonic) {
    return isMnemonicValid(mnemonic)
  }

  generateMnemonic(entropy) {
    return generateMnemonic(entropy, this.randomBufferLength)
  }

  isPrivateKeyCorrect(privateKey) {
    return utils.isPrivateKeyCorrect(privateKey)
  }

  getAccounts() {
    return this.accounts
  }

  getAccount(findProps) {
    if (!(findProps && findProps.id)) {
      throw (new Error('[getAccount] Account ID not provided'))
    }

    return find(this.accounts, findProps)
  }

  createAccount(props) {
    const { type, isReadOnly, password, accountName, ...otherProps } = props
    const extendedAccountInfo = this._getExtendedAccountInfo(password, accountName)
    const accountData = { ...otherProps, ...extendedAccountInfo }

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
      throw (new Error('[createAccount] Type of account not provided or incorrect'))
    }

    createAccountHandler.call(this, accountData)

    return accountData.id
  }

  setAccountName(password, accountId, newName) {
    const account = this.getAccount({ id: accountId })

    if (!account) {
      throw (new Error('[setAccountName] Account not found'))
    }

    // it will throw if password is incorrect
    this.checkPassword(password, account)

    return this._setAccount(account, { accountName: newName })
  }

  getPrivateKey(password, accountId) {
    const account = this.getAccount({ id: accountId, type: this.addressType })

    if (!account) {
      throw (new Error('[getPrivateKey] Account not found'))
    }

    const { salt, addresses, encrypted } = account
    const address = addresses[0]
    const dataToDecrypt = encrypted.privateKeys[address]

    if (!dataToDecrypt) {
      return null
    }

    const derivedKey = this._deriveKeyFromPassword(password, salt)
    const decryptedData = this._decryptData(dataToDecrypt, derivedKey, true)

    if (!decryptedData.length) {
      throw (new Error('[getPrivateKey] Password is incorrect'))
    }

    return decryptedData
  }

  getPrivateKeyFromMnemonic(password, accountId, keyIndex) {
    const account = this.getAccount({ id: accountId, type: this.mnemonicType })

    if (!account) {
      throw (new Error('[getPrivateKeyFromMnemonic] Account not found'))
    }

    const derivedKey = this._deriveKeyFromPassword(password, account.salt)
    const privateKey = this._generatePrivateKey(derivedKey, account, keyIndex)
    const encryptedPrivateKey = this._encryptData(privateKey, derivedKey)

    const address = utils.getAddressFromPrivateKey(privateKey)
    const addresses = [...account.addresses, address]

    const privateKeys = cloneDeep(account.encrypted.privateKeys)
    privateKeys[address] = encryptedPrivateKey

    const encrypted = cloneDeep(account.encrypted)

    this._setAccount(account, {
      addresses,
      encrypted: { ...encrypted, privateKeys },
    })

    return privateKey
  }

  checkPassword(password, account) {
    const { type, salt, addresses, encrypted } = account
    const isPrivateKey = (type === this.addressType)

    const dataToDecrypt = isPrivateKey ? encrypted.privateKeys[addresses[0]] : encrypted.mnemonic

    if (!dataToDecrypt) {
      throw (new Error('[checkPassword] Nothing to decrypt'))
    }

    const derivedKey = this._deriveKeyFromPassword(password, salt)
    const descryptedData = this._decryptData(dataToDecrypt, derivedKey, isPrivateKey)

    if (!descryptedData.length) {
      throw (new Error('[getPrivateKey] Password is incorrect'))
    }
  }

  serialize() {
    return JSON.stringify(this._getBackupData())
  }

  deserialize(backupData) {
    let data

    try {
      data = JSON.parse(backupData)
    } catch (err) {
      throw (new Error('[_deserialize] Failed to parse backup data'))
    }

    this._restoreBackupData(data)

    return data
  }

  _deriveKeyFromPassword(password, salt) {
    return utils.deriveKeyFromPassword(password, this.scryptParams, this.derivedKeyLength, salt)
  }

  _createMnemonicAccount(props) {
    const { id, salt, derivedKey, mnemonic, derivationPath, accountName } = props
    const _derivationPath = derivationPath || this.defaultDerivationPath

    if (!this.isMnemonicValid(mnemonic)) {
      throw (new Error('[_createMnemonicAccount] Invalid mnemonic'))
    }

    const paddedMnemonic = utils.leftPadString(mnemonic, ' ', 120)
    const hdRoot = new Mnemonic(mnemonic).toHDPrivateKey().xprivkey

    const hdRootKey = new bitcore.HDPrivateKey(hdRoot)
    const hdPath = hdRootKey.derive(_derivationPath).xprivkey

    this.accounts.push({
      type: this.mnemonicType,
      id,
      salt,
      accountName,
      isReadOnly: false,
      hdIndex: 0,
      addresses: [],
      derivationPath: _derivationPath,
      encrypted: {
        privateKeys: {},
        mnemonic: this._encryptData(paddedMnemonic, derivedKey),
        hdRoot: this._encryptData(hdRoot, derivedKey),
        hdPath: this._encryptData(hdPath, derivedKey),
      },
    })
  }

  _createReadOnlyMnemonicAccount(props) {
    const { id, salt, bip32XPublicKey, accountName } = props

    this.accounts.push({
      type: this.mnemonicType,
      id,
      salt,
      accountName,
      bip32XPublicKey,
      isReadOnly: true,
      hdIndex: 0,
      addresses: [],
      encrypted: {
        privateKeys: {},
      },
    })
  }

  _createAddressAccount(props) {
    const { id, salt, derivedKey, privateKey, accountName } = props

    if (!this.isPrivateKeyCorrect(privateKey)) {
      throw (new Error('[_createAddressAccount] Private Key is incorrect'))
    }

    const address = utils.getAddressFromPrivateKey(privateKey)
    const privateKeys = {}
    privateKeys[address] = this._encryptData(privateKey, derivedKey, true)

    this.accounts.push({
      type: this.addressType,
      id,
      salt,
      accountName,
      isReadOnly: false,
      addresses: [address],
      encrypted: { privateKeys },
    })
  }

  _createReadOnlyAddressAccount(props) {
    const { id, address, accountName } = props

    this.accounts.push({
      type: this.addressType,
      id,
      accountName,
      isReadOnly: true,
      addresses: [address],
      encrypted: {
        privateKeys: {},
      },
    })
  }

  _getExtendedAccountInfo(password, accountName) {
    const salt = utils.generateSalt(this.saltByteCount)
    const id = uuidv4()

    return {
      id,
      salt,
      accountName: accountName || `Account ${this.accounts.length + 1}`,
      derivedKey: this._deriveKeyFromPassword(password, salt),
    }
  }

  _encryptData(dataToEncrypt, derivedKey, isPrivateKey = false) {
    return encryption.encryptData({
      derivedKey,
      isPrivateKey,
      data: dataToEncrypt,
      encryptionType: this.defaultEncryptionType,
    })
  }

  _decryptData(dataToDecrypt, derivedKey, isPrivateKey = false) {
    return encryption.decryptData({
      derivedKey,
      isPrivateKey,
      data: dataToDecrypt,
    })
  }

  _generatePrivateKey(derivedKey, account, keyIndex) {
    const { isReadOnly, bip32XPublicKey, encrypted, hdIndex } = account

    let keyIndexToDerive

    if (keyIndex != null) {
      keyIndexToDerive = keyIndex
    } else {
      keyIndexToDerive = hdIndex
      this._setAccount(account, { hdIndex: hdIndex + 1 })
    }

    const hdRoot = isReadOnly
      ? new bitcore.HDPublicKey(bip32XPublicKey)
      : new bitcore.HDPrivateKey(this._decryptData(encrypted.hdRoot, derivedKey))

    const hdPrivateKey = hdRoot.derive(keyIndexToDerive)

    const privateKeyBuffer = hdPrivateKey.privateKey.toBuffer()
    const privateKeyBufferLength = privateKeyBuffer.length

    let privateKey = privateKeyBuffer.toString('hex')

    if ((privateKeyBufferLength < 16) || (privateKeyBufferLength > 32)) {
      throw (new Error('[_generatePrivateKey] Private key buffer has inappropriate size'))
    } else if (privateKeyBufferLength < 32) {
      privateKey = utils.leftPadString(privateKey, '0', 64)
    }

    return privateKey
  }

  _setAccount(account, props) {
    const accountIndex = this._getAccountIndex(account.id)

    if (accountIndex === -1) {
      throw (new Error('[_setAccount] Account not found'))
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
      scryptOptions,
      derivedKeyLength,
      version,
    } = this

    return {
      accounts,
      defaultDerivationPath,
      defaultEncryptionType,
      scryptOptions,
      derivedKeyLength,
      version,
    }
  }

  _restoreBackupData(backupData) {
    if (backupData.version === 1) {
      const {
        accounts,
        defaultDerivationPath,
        defaultEncryptionType,
        scryptOptions,
        derivedKeyLength,
      } = backupData

      this.accounts = accounts || []
      this.defaultDerivationPath = defaultDerivationPath || this.defaultDerivationPath
      this.defaultEncryptionType = defaultEncryptionType || this.defaultEncryptionType
      this.scryptOptions = scryptOptions || this.scryptOptions
      this.derivedKeyLength = derivedKeyLength || this.derivedKeyLength
      this.version = 1
    }
  }
}

module.exports = Keystore
