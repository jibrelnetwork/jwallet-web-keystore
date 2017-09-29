const CryptoJS = require('crypto-js')
const EC = require('elliptic').ec
const bitcore = require('bitcore-lib')
const Mnemonic = require('bitcore-mnemonic')
const scrypt = require('scrypt')
const uuidv4 = require('uuid/v4')
const { cloneDeep, find, findIndex } = require('lodash')

const encryption = require('./encryption')
const leftPadString = require('./leftPadString')

const { Random, Hash } = bitcore.crypto
const ec = new EC('secp256k1')
const { encryptData, decryptData } = encryption

class AccountsManager {
  constructor() {
    this.accounts = []
    this.defaultDerivationPath = "m/44'/0'/0'/0"
    this.defaultEncryptionType = 'nacl.secretbox'
    this.randomBufferLength = 32
    this.saltByteCount = 32
    this.mnemonicType = 'mnemonic'
    this.privateKeyType = 'privateKey'
    this.scryptOptions = { N: 2 ** 18, r: 8, p: 1 }
    this.derivedKeyLength = 32
    this.version = 1
  }

  static isMnemonicValid(mnemonic) {
    const words = mnemonic.split(' ')
    const mnemonic1 = words.slice(0, 12).join(' ')
    const mnemonic2 = words.slice(12, 24).join(' ')

    const isMnemonic1Valid = Mnemonic.isValid(mnemonic1, Mnemonic.Words.ENGLISH)
    const isMnemonic2Valid = Mnemonic.isValid(mnemonic2, Mnemonic.Words.ENGLISH)

    return (isMnemonic1Valid && isMnemonic2Valid)
  }

  static isPrivateKeyCorrect(key, length) {
    const is0x = (key.indexOf('0x') === 0)
    const keyLength = is0x ? (key.length - 2) : key.length

    if (keyLength !== length) {
      throw (new Error(`[isKeyCorrect] Key ${key} is incorrect`))
    }

    const keyRe = /^(0x)([A-F\d]+)$/i

    return keyRe.test(key)
  }

  generateMnemonic(entropy) {
    const dataList = Mnemonic.Words.ENGLISH
    const hashedEntropy = this._getHashedEntropy(entropy)

    // One mnemonic is set of 12 words. So we need two ones.
    const mnemonic1 = hashedEntropy ? new Mnemonic(hashedEntropy, dataList) : new Mnemonic(dataList)
    const mnemonic2 = hashedEntropy ? new Mnemonic(hashedEntropy, dataList) : new Mnemonic(dataList)

    return `${mnemonic1.toString()} ${mnemonic2.toString()}`
  }

  getAccounts() {
    return this.accounts
  }

  getAccount(findProps) {
    if (!findProps.id) {
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
        ? this._createReadOnlyMnemonicAccount.bind(this)
        : this._createMnemonicAccount.bind(this)
    } else if (type === this.privateKeyType) {
      createAccountHandler = isReadOnly
        ? this._createReadOnlyPrivateKeyAccount.bind(this)
        : this._createPrivateKeyAccount.bind(this)
    } else {
      throw (new Error('[createAccount] Type of account not provided'))
    }

    createAccountHandler(accountData)

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
    const account = this.getAccount({ id: accountId, type: this.privateKeyType })

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
    const descryptedData = this._decryptData(dataToDecrypt, derivedKey, true)

    if (!descryptedData.length) {
      throw (new Error('[getPrivateKey] Password is incorrect'))
    }

    return descryptedData
  }

  getPrivateKeyFromMnemonic(password, accountId, keyIndex) {
    const account = this.getAccount(accountId, this.mnemonicType)

    if (!account) {
      throw (new Error('[getPrivateKeyFromMnemonic] Account not found'))
    }

    const derivedKey = this._deriveKeyFromPassword(password, account.salt)
    const privateKey = this._generatePrivateKey(derivedKey, account, keyIndex)
    const address = this._computeAddressFromPrivateKey(privateKey)
    const encryptedPrivateKey = this._encryptData(privateKey, derivedKey)

    const addresses = [...account.addresses, address]

    const privateKeys = cloneDeep(account.encrypted.privateKeys)
    privateKeys[address] = encryptedPrivateKey

    const encrypted = cloneDeep(account.encrypted)

    this.setAccount(account, {
      addresses,
      encrypted: { ...encrypted, privateKeys },
    })

    return privateKey
  }

  checkPassword(password, account) {
    const { type, salt, addresses, encrypted } = account
    const isPrivateKey = (type === this.privateKeyType)

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

  static _concatEntropyBuffers(entropyBuffer, randomBuffer) {
    const totalEntropy = Buffer.concat([entropyBuffer, randomBuffer])

    if (totalEntropy.length !== entropyBuffer.length + randomBuffer.length) {
      throw (new Error('[_concatAndSha256] Concatenation of entropy buffers failed.'))
    }

    return Hash.sha256(totalEntropy)
  }

  static _computeAddressFromPrivateKey(privateKey) {
    const keyEncodingType = 'hex'

    const keyPair = ec.genKeyPair()
    keyPair._importPrivate(privateKey, keyEncodingType)

    const compact = false

    const publicKey = keyPair.getPublic(compact, keyEncodingType).slice(2)
    const publicKeyWordArray = CryptoJS.enc.Hex.parse(publicKey)
    const hash = CryptoJS.SHA3(publicKeyWordArray, { outputLength: 256 })
    const address = hash.toString(CryptoJS.enc.Hex).slice(24)

    return `0x${address}`
  }

  static _decryptData(dataToDecrypt, derivedKey, isPrivateKey = false) {
    return decryptData({
      derivedKey,
      isPrivateKey,
      data: dataToDecrypt,
    })
  }

  _getHashedEntropy(entropy) {
    if (!entropy) {
      return null
    } else if (typeof entropy !== 'string') {
      throw (new Error('[_getHashedEntropy] Entropy is set but not a string.'))
    }

    const entropyBuffer = Buffer.from(entropy)
    const randomBuffer = Random.getRandomBuffer(this.randomBufferLength)

    return this._concatEntropyBuffers(entropyBuffer, randomBuffer).slice(0, 16)
  }

  _generateSalt(byteCount = this.saltByteCount) {
    return Random.getRandomBuffer(byteCount).toString('base64')
  }

  _deriveKeyFromPassword(password, salt) {
    const derivedKey = scrypt.hashSync(password, this.scryptOptions, this.derivedKeyLength, salt)

    return new Uint8Array(derivedKey)
  }

  _createMnemonicAccount(props) {
    const { id, salt, derivedKey, mnemonic, derivationPath, accountName } = props
    const _derivationPath = derivationPath || this.defaultDerivationPath

    if (!this.isMnemonicValid(mnemonic)) {
      throw (new Error('[_createMnemonicAccount] Invalid mnemonic'))
    }

    const paddedMnemonic = leftPadString(mnemonic, ' ', 120)
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

  _createPrivateKeyAccount(props) {
    const { id, salt, derivedKey, privateKey, accountName } = props

    const address = this._computeAddressFromPrivateKey(privateKey)
    const privateKeys = {}
    privateKeys[address] = this._encryptData(privateKey, derivedKey, true)

    this.accounts.push({
      type: this.privateKeyType,
      id,
      salt,
      accountName,
      isReadOnly: false,
      addresses: [address],
      encrypted: { privateKeys },
    })
  }

  _createReadOnlyPrivateKeyAccount(props) {
    const { id, address, accountName } = props

    this.accounts.push({
      type: this.privateKeyType,
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
    const salt = this._generateSalt()
    const id = uuidv4()

    return {
      id,
      salt,
      accountName: accountName || `Account ${this.accounts.length + 1}`,
      derivedKey: this._deriveKeyFromPassword(password, salt),
    }
  }

  _encryptData(dataToEncrypt, derivedKey, isPrivateKey = false) {
    return encryptData({
      derivedKey,
      isPrivateKey,
      data: dataToEncrypt,
      encryptionType: this.defaultEncryptionType,
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
      : new bitcore.HDPrivateKey(this._decryptString(encrypted.hdRoot, derivedKey))

    const hdPrivateKey = hdRoot.derive(keyIndexToDerive)
    const privateKeyBuffer = hdPrivateKey.privateKey.toBuffer()
    const privateKeyBufferLength = privateKeyBuffer.length

    let privateKey = privateKeyBuffer.toString('hex')

    if ((privateKeyBufferLength < 16) || (privateKeyBufferLength > 32)) {
      throw (new Error('[_generatePrivateKey] Private key buffer has inappropriate size'))
    } else if (privateKeyBufferLength < 32) {
      privateKey = leftPadString(privateKey, '0', 64)
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

module.exports = AccountsManager
