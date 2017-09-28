const bitcore = require('bitcore-lib')
const nacl = require('tweetnacl')

const { randomBytes, secretbox, util } = nacl

function encryptString(stringToEncrypt, derivedKey, encryptionType) {
  if (encryptionType === 'nacl.secretbox') {
    return encryptStringNaclSecretbox(stringToEncrypt, derivedKey)
  }

  throw (new Error(`[encryptString] Encryption type ${encryptionType} is not supported`))
}

function encryptStringNaclSecretbox(stringToEncrypt, derivedKey) {
  const nonce = getNonce()
  const encryptedObject = secretbox(util.decodeUTF8(stringToEncrypt), nonce, derivedKey)

  return encodeEncryptedData(encryptedObject, nonce, 'nacl.secretbox')
}

function encryptHdRoot(hdRoot, derivedKey, encryptionType) {
  return encryptString(hdRoot, derivedKey, encryptionType)
}

function encryptHdPath(hdRoot, derivationPath, derivedKey, encryptionType) {
  const hdRootKey = new bitcore.HDPrivateKey(hdRoot)
  const hdPath = hdRootKey.derive(derivationPath).xprivkey

  return encryptString(hdPath, derivedKey, encryptionType)
}

function encryptMnemonic(mnemonic, derivedKey, encryptionType) {
  const paddedMnemonic = leftPadString(mnemonic, ' ', 120)

  return encryptString(paddedMnemonic, derivedKey, encryptionType)
}

function encryptPrivateKey(privateKey, derivedKey, encryptionType) {
  const nonce = getNonce()
  const privateKeyArray = naclDecodeHex(privateKey)
  const encryptedPrivateKey = secretbox(privateKeyArray, nonce, derivedKey)

  return encodeEncryptedData(encryptedPrivateKey, nonce, encryptionType)
}

function encodeEncryptedData(encryptedData, nonce, encryptionType) {
  return {
    type: encryptionType,
    nonce: util.encodeBase64(nonce),
    encryptedData: util.encodeBase64(encryptedData),
  }
}

function getNonce() {
  return randomBytes(secretbox.nonceLength)
}

function leftPadString (stringToPad, padChar, totalLength) {
  const leftPadLength = totalLength - stringToPad.length
  let leftPad = ''

  for (let i = 0; i < leftPadLength; i += 1) {
    leftPad += padChar
  }

  return `${leftPad}${stringToPad}`
}

function naclDecodeHex(privateKey) {
  const privateKeyBase64 = (new Buffer(privateKey, 'hex')).toString('base64')

  return util.decodeBase64(privateKeyBase64)
}

module.exports = {
  encryptMnemonic,
  encryptHdRoot,
  encryptHdPath,
  encryptPrivateKey,
}
