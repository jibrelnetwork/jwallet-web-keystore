// @flow

import nacl from 'tweetnacl'
import util from 'tweetnacl-util'

type DecodedEncryptedData = {|
  +data: Uint8Array,
  +nonce: Uint8Array,
|}

type EncryptPayload = {|
  +data: string,
  +derivedKey: Uint8Array,
  +encryptionType: string,
  +isPrivateKey: boolean,
|}

type DecryptPayload = {|
  data: {|
    +data: string,
    +nonce: string,
  |},
  +derivedKey: Uint8Array,
  +encryptionType: string,
  +isPrivateKey: boolean,
|}

function getNonce(nonceLength: number): Uint8Array {
  return nacl.randomBytes(nonceLength)
}

function decodePrivateKey(privateKey: string): Uint8Array {
  const privateKeyBase: string = (Buffer.from(privateKey)).toString('base64')

  return util.decodeBase64(privateKeyBase)
}

function encodeEncryptedData(encryptedData: Uint8Array, nonce: Uint8Array): EncryptedData {
  return {
    nonce: util.encodeBase64(nonce),
    data: util.encodeBase64(encryptedData),
  }
}

function encryptNaclSecretbox(
  data: string,
  derivedKey: Uint8Array,
  isPrivateKey: boolean,
): EncryptedData {
  const nonce: Uint8Array = getNonce(nacl.secretbox.nonceLength)
  const dataToEncrypt: Uint8Array = isPrivateKey ? decodePrivateKey(data) : util.decodeUTF8(data)
  const encryptedData: ?Uint8Array = nacl.secretbox(dataToEncrypt, nonce, derivedKey)

  if ((encryptedData === null) || (encryptedData === undefined)) {
    throw new Error('Password is invalid')
  }

  return encodeEncryptedData(encryptedData, nonce)
}

export function encryptData(payload: EncryptPayload): EncryptedData {
  const {
    data,
    derivedKey,
    encryptionType,
    isPrivateKey,
  } = payload

  if (encryptionType !== 'nacl.secretbox') {
    throw new Error(`Encryption type ${encryptionType} is not supported`)
  }

  return encryptNaclSecretbox(data, derivedKey, isPrivateKey)
}

function decodeEncryptedData(data: EncryptedData): DecodedEncryptedData {
  return {
    data: util.decodeBase64(data.data),
    nonce: util.decodeBase64(data.nonce),
  }
}

function encodePrivateKey(privateKey: Uint8Array): string {
  const privateKeyBase: string = util.encodeBase64(privateKey)

  return (Buffer.from(privateKeyBase, 'base64')).toString()
}

function decryptNaclSecretbox(
  data: EncryptedData,
  derivedKey: Uint8Array,
  isPrivateKey: boolean,
): string {
  const decoded: DecodedEncryptedData = decodeEncryptedData(data)
  const decryptedData: ?Uint8Array = nacl.secretbox.open(decoded.data, decoded.nonce, derivedKey)

  if ((decryptedData === null) || (decryptedData === undefined)) {
    throw new Error('Password is invalid')
  }

  return isPrivateKey ? encodePrivateKey(decryptedData) : util.encodeUTF8(decryptedData)
}

export function decryptData(payload: DecryptPayload): string {
  const {
    data,
    derivedKey,
    encryptionType,
    isPrivateKey,
  } = payload

  if (encryptionType !== 'nacl.secretbox') {
    throw new Error(`Decryption type ${encryptionType} is not supported`)
  }

  return decryptNaclSecretbox(data, derivedKey, isPrivateKey)
}
