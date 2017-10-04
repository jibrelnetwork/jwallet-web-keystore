const scrypt = require('scrypt.js')
const cryptoJS = require('crypto-js')
const EC = require('elliptic').ec
const { Random } = require('bitcore-lib').crypto

const ec = new EC('secp256k1')

function isHashStringValid(hash, length) {
  const is0x = (hash.indexOf('0x') === 0)
  const hashLength = is0x ? (hash.length - 2) : hash.length

  if (hashLength !== length) {
    return false
  }

  const hashRe = new RegExp(`^(0x)?([A-F\\d]{${length}})$`, 'i')

  return hashRe.test(hash)
}

function getAddressFromPublicKey(publicKey) {
  const publicKeyWordArray = cryptoJS.enc.Hex.parse(publicKey)
  const hash = cryptoJS.SHA3(publicKeyWordArray, { outputLength: 256 })
  const address = hash.toString(cryptoJS.enc.Hex).slice(24)

  return add0x(address)
}

function getAddressFromPrivateKey(privateKey) {
  const keyEncodingType = 'hex'

  const keyPair = ec.genKeyPair()
  keyPair._importPrivate(privateKey, keyEncodingType)

  const compact = false

  const publicKey = keyPair.getPublic(compact, keyEncodingType).slice(2)

  return getAddressFromPublicKey(publicKey)
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
  isHashStringValid,
  getAddressFromPublicKey,
  getAddressFromPrivateKey,
  deriveKeyFromPassword,
  leftPadString,
  generateSalt,
  add0x,
}
