const scrypt = require('scrypt.js')
const cryptoJS = require('crypto-js')
const EC = require('elliptic').ec
const { Random } = require('bitcore-lib').crypto

const ec = new EC('secp256k1')
const HEX_PREFIX = /^0x/i

function isAddressValid(address) {
  return isNormalizedAddress(address) || isChecksumAddressValid(address)
}

function isNormalizedAddress(address) {
  return (/^0x[0-9a-f]{40}$/.test(address) || /^0x[0-9A-F]{40}$/.test(address))
}

function isChecksumAddressValid(address) {
  return (/^0x[0-9a-fA-F]{40}$/i.test(address) && getChecksum(address) === address)
}

function getChecksum(address) {
  const addressLowerCase = strip0x(address).toLowerCase()
  const hash = cryptoJS.SHA3(addressLowerCase, { outputLength: 256 }).toString(cryptoJS.enc.Hex)

  const checksum = addressLowerCase
    .split('')
    .map((symbol, index) => ((parseInt(hash[index], 16) >= 8) ? symbol.toUpperCase() : symbol))
    .join('')

  return add0x(checksum)
}

function isPrivateKeyValid(privateKey) {
  return (/^0x[0-9a-fA-F]{64}$/i.test(privateKey))
}

function getAddressFromPublicKey(publicKey) {
  const keyPair = ec.keyFromPublic(publicKey, 'hex')

  return getAddressFromKeyPair(keyPair)
}

function getAddressFromPrivateKey(privateKey) {
  const keyPair = ec.genKeyPair()
  keyPair._importPrivate(strip0x(privateKey), 'hex')

  return getAddressFromKeyPair(keyPair)
}

function getAddressFromKeyPair(keyPair) {
  const compact = false

  const publicKey = keyPair.getPublic(compact, 'hex').slice(2)
  const publicKeyWordArray = cryptoJS.enc.Hex.parse(publicKey)
  const hash = cryptoJS.SHA3(publicKeyWordArray, { outputLength: 256 })
  const address = hash.toString(cryptoJS.enc.Hex).slice(24)

  return getChecksum(address)
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

function strip0x(data) {
  return data.replace(HEX_PREFIX, '')
}

function add0x(data) {
  if (HEX_PREFIX.test(data)) {
    return data
  }

  return `0x${data}`
}

module.exports = {
  isAddressValid,
  isPrivateKeyValid,
  getAddressFromPublicKey,
  getAddressFromPrivateKey,
  deriveKeyFromPassword,
  leftPadString,
  generateSalt,
  add0x,
}
