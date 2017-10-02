const nacl = require('tweetnacl')
const util = require('tweetnacl-util')

const { randomBytes, secretbox } = nacl

function encryptData(props) {
  const { encryptionType, ...otherProps } = props

  if (encryptionType === 'nacl.secretbox') {
    return encryptNaclSecretbox(otherProps)
  }

  throw (new Error(`Encryption type ${encryptionType} is not supported`))
}

function encryptNaclSecretbox(props) {
  const { data, derivedKey, isPrivateKey } = props

  const nonce = getNonce()
  const dataToEncrypt = isPrivateKey ? decodePrivateKey(data) : util.decodeUTF8(data)
  const encryptedData = secretbox(dataToEncrypt, nonce, derivedKey)

  return encodeEncryptedData(encryptedData, nonce, 'nacl.secretbox')
}

function encodeEncryptedData(encryptedData, nonce, encryptionType) {
  return {
    encryptionType,
    nonce: util.encodeBase64(nonce),
    encryptedData: util.encodeBase64(encryptedData),
  }
}

function decodeEncryptedData(data) {
  return {
    encryptedData: util.decodeBase64(data.encryptedData),
    nonce: util.decodeBase64(data.nonce),
  }
}

function getNonce() {
  return randomBytes(secretbox.nonceLength)
}

function decodePrivateKey(privateKey) {
  const privateKeyBase64 = (Buffer.from(privateKey)).toString('base64')

  return util.decodeBase64(privateKeyBase64)
}

function encodePrivateKey(privateKey) {
  const privateKeyBase64 = util.encodeBase64(privateKey)

  return (Buffer.from(privateKeyBase64, 'base64')).toString()
}

function decryptData(props) {
  const { encryptionType } = props.data

  if (encryptionType === 'nacl.secretbox') {
    return decryptNaclSecretbox(props)
  }

  throw (new Error(`Decryption type ${encryptionType} is not supported`))
}

function decryptNaclSecretbox(props) {
  const { data, derivedKey, isPrivateKey } = props

  const { nonce, encryptedData } = decodeEncryptedData(data)
  const decryptedData = secretbox.open(encryptedData, nonce, derivedKey)

  if (decryptedData == null) {
    throw new Error('Decryption failed')
  }

  return isPrivateKey ? encodePrivateKey(decryptedData) : util.encodeUTF8(decryptedData)
}

module.exports = { encryptData, decryptData }
