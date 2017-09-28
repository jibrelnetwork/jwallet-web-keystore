const Promise = require('bluebird')
const CryptoJS = require('crypto-js')
const Transaction = require('ethereumjs-tx')
const EC = require('elliptic').ec
const bitcore = require('bitcore-lib')
const Mnemonic = require('bitcore-mnemonic')
const scryptAsync = require('scrypt-async')
const uuidv4 = require('uuid/v4')

const encryption = require('./encryption')

const { Random, Hash } = bitcore.crypto
const ec = new EC('secp256k1')
const { encryptMnemonic, encryptHdRoot, encryptHdPath, encryptPrivateKey } = encryption

class AccountsManager {
  constructor(props) {
    super(props)

    this.accounts = []
    this.defaultDerivationPath = "m/44'/0'/0'/0"
    this.defaultEncryptionType = 'nacl.secretbox'
    this.randomBufferLength = 32
    this.saltByteCount = 32
    this.mnemonicType = 'mnemonic'
    this.privateKeyType = 'privateKey'

    this.scryptOptions = {
      logN: 18,
      r: 8,
      p: 1,
      dkLen: 32,
      interruptStep: 200,
      encoding: null,
    }
  }

  getAccounts() {
    return this.accounts
  }

  createAccount(props) {
    const { type, isReadOnly, password, accountName, ...otherProps } = props
    const extendedAccountInfo = this._getExtendedAccountInfo(password, accountName)
    const accountData = { ...otherProps, ...extendedAccountInfo }

    let createHandler

    if (type === this.mnemonicType) {
      createHandler = isReadOnly ? _createReadOnlyMnemonicAccount : _createMnemonicAccount
    } else if (type === this.privateKeyType) {
      createHandler = isReadOnly ? _createReadOnlyPrivateKeyAccount : _createPrivateKeyAccount
    }

    createHandler(accountData)

    return accountData.id
  }

  setAccountName(props) {
    const { password, recordId, newName } = props
  }

  generateMnemonic(entropy) {
    const dataList = Mnemonic.Words.ENGLISH
    const hashedEntropy = _getHashedEntropy(entropy)
    const mnemonic = hashedEntropy ? new Mnemonic(hashedEntropy, dataList) : new Mnemonic(dataList)

    return mnemonic.toString()
  }

  isMnemonicValid(mnemonic) {
    return Mnemonic.isValid(mnemonic, Mnemonic.Words.ENGLISH)
  }

  isKeyCorrect(key, length) {
    const is0x = (key.indexOf('0x') === 0)
    const keyLength = is0x ? (key.length - 2) : key.length

    if (keyLength !== length) {
      throw (new Error(`[isKeyCorrect] Key ${key} is incorrect`))
    }

    const keyRe = /^(0x)([A-F\d]+)$/i

    return keyRe.test(key)
  }

  getPrivateKey(recordId) {

  }

  getPrivateKeyFromMnemonic(recordId, addressNumber) {

  }

  _generateId() {
    return uuidv4()
  }

  _getHashedEntropy(entropy) {
    if (!entropy) {
      return null
    } else if (typeof entropy !== 'string') {
      throw (new Error('[generateMnemonic] Entropy is set but not a string.'))
    }

    const entropyBuffer = new Buffer(entropy)
    const randomBuffer = Random.getRandomBuffer(this.randomBufferLength)

    return this._concatAndSha256(entropyBuffer, randomBuffer).slice(0, 16)
  }

  _concatAndSha256(entropyBuffer, randomBuffer) {
    const totalEntropy = Buffer.concat([entropyBuffer, randomBuffer])

    if (totalEntropy.length !== entropyBuffer.length + randomBuffer.length) {
      throw (new Error('[generateMnemonic] Concatenation of entropy buffers failed.'))
    }

    return Hash.sha256(totalEntropy)
  }

  _generateSalt(byteCount = this.saltByteCount) {
    return Random.getRandomBuffer(byteCount).toString('base64')
  }

  _deriveKeyFromPassword(password, salt) {
    return new Promise(resolve => scrypt(password, salt, this.scryptOptions, resolve))
      .then(derivedKey => new Uint8Array(derivedKey))
  }

  _createMnemonicAccount(props) {
    const { id, salt, derivedKey, mnemonic, derivationPath, accountName } = props

    if (!isMnemonicValid(mnemonic)) {
      throw (new Error('[_createMnemonicAccount] Invalid mnemonic'))
    }

    const hdRoot = new Mnemonic(mnemonic).toHDPrivateKey().xprivkey
    const encryptionType = this.defaultEncryptionType

    this.accounts.push({
      type: this.mnemonicType,
      id,
      salt,
      accountName,
      isReadOnly: false,
      hdIndex: 0,
      addresses: [],
      encrypted: {
        privateKeys: {},
        mnemonic: encryptMnemonic(mnemonic, derivedKey, encryptionType),
        hdRoot: encryptHdRoot(hdRoot, derivedKey, encryptionType),
        hdPath: encryptHdPath(hdRoot, derivationPath, derivedKey, encryptionType),
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
    const encryptionType = this.defaultEncryptionType
    const address = _computeAddressFromPrivateKey(privateKey)
    const privateKeys[address] = encryptPrivateKey(privateKey, derivedKey, encryptionType)

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

  _getExtendedAccountInfo(password, accountName) {
    const salt = this._generateSalt()
    const id = this._generateId()

    return {
      id,
      salt,
      accountName: accountName || id,
      derivedKey: this._deriveKeyFromPassword(password, salt),
    }
  }
}

module.exports = KeysManager
