const scrypt = require('scrypt.js')
const cryptoJS = require('crypto-js')
const EC = require('elliptic').ec
const { Random } = require('bitcore-lib').crypto

const ec = new EC('secp256k1')

function isHexStringValid(hex, length) {
  const requiredLengthWithPrefix = length + '0x'.length

  if (hex.length !== requiredLengthWithPrefix) {
    return false
  }

  const hexRe = new RegExp(`^(0x)([A-F\\d]{${length}})$`, 'i')

  return hexRe.test(hex)
}

function getAddressFromPublicKey(publicKey) {
  const keyPair = ec.keyFromPublic(publicKey, 'hex')

  return getAddressFromKeyPair(keyPair)
}

function getAddressFromPrivateKey(privateKey) {
  const keyPair = ec.genKeyPair()
  keyPair._importPrivate(privateKey, 'hex')

  return getAddressFromKeyPair(keyPair)
}

function getAddressFromKeyPair(keyPair) {
  const compact = false

  const publicKey = keyPair.getPublic(compact, 'hex').slice(2)
  const publicKeyWordArray = cryptoJS.enc.Hex.parse(publicKey)
  const hash = cryptoJS.SHA3(publicKeyWordArray, { outputLength: 256 })
  const address = hash.toString(cryptoJS.enc.Hex).slice(24)

  return add0x(address)
}

function deriveKeyFromPassword(password, scryptParams, derivedKeyLength, salt) {
  const { N, r, p } = scryptParams
  const derivedKey = scrypt(password, salt, N, r, p, derivedKeyLength)

  return new Uint8Array(derivedKey)
}

function leftPadString(stringToPad, padChar, totalLength) {
  const leftPadLength = totalLength - stringToPad.length
  let leftPad = ''

  for (let i = 0; i < leftPadLength; i += 1) {
    leftPad += padChar
  }

  return `${leftPad}${stringToPad}`
}

function generateSalt(byteCount) {
  return Random.getRandomBuffer(byteCount).toString('base64')
}

function add0x(data) {
  if (data.indexOf('0x') === 0) {
    return data
  }

  return `0x${data}`
}

module.exports = {
  isHexStringValid,
  getAddressFromPublicKey,
  getAddressFromPrivateKey,
  deriveKeyFromPassword,
  leftPadString,
  generateSalt,
  add0x,
}
