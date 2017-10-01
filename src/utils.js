const scrypt = require('scrypt')
const cryptoJS = require('crypto-js')
const EC = require('elliptic').ec
const { Random } = require('bitcore-lib').crypto

const ec = new EC('secp256k1')
const privateKeyLength = 64

function isPrivateKeyCorrect(key) {
  const is0x = (key.indexOf('0x') === 0)
  const keyLength = is0x ? (key.length - 2) : key.length

  if (keyLength !== privateKeyLength) {
    throw (new Error(`[isKeyCorrect] Key ${key} is incorrect`))
  }

  const keyRe = /^(0x)([A-F\d]+)$/i

  return keyRe.test(key)
}

function getAddressFromPrivateKey(privateKey) {
  const keyEncodingType = 'hex'

  const keyPair = ec.genKeyPair()
  keyPair._importPrivate(privateKey, keyEncodingType)

  const compact = false

  const publicKey = keyPair.getPublic(compact, keyEncodingType).slice(2)
  const publicKeyWordArray = cryptoJS.enc.Hex.parse(publicKey)
  const hash = cryptoJS.SHA3(publicKeyWordArray, { outputLength: 256 })
  const address = hash.toString(cryptoJS.enc.Hex).slice(24)

  return `0x${address}`
}

function deriveKeyFromPassword(password, scryptParams, derivedKeyLength, salt) {
  const derivedKey = scrypt.hashSync(password, scryptParams, derivedKeyLength, salt)

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

module.exports = {
  isPrivateKeyCorrect,
  getAddressFromPrivateKey,
  deriveKeyFromPassword,
  leftPadString,
  generateSalt,
}
