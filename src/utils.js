// @flow

import scrypt from 'scrypt.js'
import cryptoJS from 'crypto-js'
import { crypto } from 'bitcore-lib'
import { ec as EC } from 'elliptic'

type KeyPair = {
  getPublic: (boolean, 'hex') => string,
  _importPrivate: (string, 'hex') => void,
}

/* eslint-disable no-use-before-define */
type KeyWordArray = {
  words: Array<number>,
  sigBytes: number,
  toString: (KeyWordArrayEncoder) => string,
}

type KeyWordArrayEncoder = {
  parse: (string) => KeyWordArray,
  stringify: (KeyWordArray) => string,
}
/* eslint-enable no-use-before-define */

const RE_HEX_PREFIX: RegExp = /^0x/i
const ENCODER: KeyWordArrayEncoder = cryptoJS.enc.Hex

const ec: {
  genKeyPair: () => KeyPair,
  keyFromPublic: (string, 'hex') => KeyPair,
} = new EC('secp256k1')

function strip0x(data: string): string {
  return data.replace(RE_HEX_PREFIX, '')
}

export function add0x(data: string): string {
  if (RE_HEX_PREFIX.test(data)) {
    return data
  }

  return `0x${data}`
}

function getChecksum(address: string): string {
  const addressLowerCase: string = strip0x(address).toLowerCase()
  const hash: string = cryptoJS.SHA3(addressLowerCase, { outputLength: 256 }).toString(ENCODER)

  const checksum: string = addressLowerCase
    .split('')
    .map((symbol: string, index: number) => ((parseInt(hash[index], 16) >= 8)
      ? symbol.toUpperCase()
      : symbol)
    )
    .join('')

  return add0x(checksum)
}

function checkNormalizedAddress(address: string): boolean {
  return (/^0x[0-9a-f]{40}$/.test(address) || /^0x[0-9A-F]{40}$/.test(address))
}

export function checkChecksumAddressValid(address: string): boolean {
  return (/^0x[0-9a-fA-F]{40}$/i.test(address) && getChecksum(address) === address)
}

export function checkAddressValid(address: string): boolean {
  return checkNormalizedAddress(address) || checkChecksumAddressValid(address)
}

export function checkPrivateKeyValid(privateKey: string): boolean {
  return (/^0x[0-9a-fA-F]{64}$/i.test(privateKey))
}

function getAddressFromKeyPair(keyPair: KeyPair): string {
  const isCompact: boolean = false
  const publicKey: string = keyPair.getPublic(isCompact, 'hex').slice(2)
  const publicKeyWordArray: KeyWordArray = ENCODER.parse(publicKey)
  const hash: KeyWordArray = cryptoJS.SHA3(publicKeyWordArray, { outputLength: 256 })
  const address: string = hash.toString(ENCODER).slice(24)

  return getChecksum(address)
}

export function getAddressFromPublicKey(publicKey: string): string {
  const keyPair: KeyPair = ec.keyFromPublic(publicKey, 'hex')

  return getAddressFromKeyPair(keyPair)
}

export function getAddressFromPrivateKey(privateKey: string): string {
  const keyPair: KeyPair = ec.genKeyPair()
  keyPair._importPrivate(strip0x(privateKey), 'hex')

  return getAddressFromKeyPair(keyPair)
}

export function deriveKeyFromPassword(
  password: string,
  scryptParams: ScryptParams,
  derivedKeyLength: number,
  salt: string,
): Uint8Array {
  const { N, r, p } = scryptParams
  const derivedKey: Buffer = scrypt(password, salt, N, r, p, derivedKeyLength)

  return new Uint8Array(derivedKey)
}

export function leftPadString(stringToPad: string, padChar: string, totalLength: number) {
  const leftPad: string = padChar.repeat(totalLength - stringToPad.length)

  return `${leftPad}${stringToPad}`
}

export function generateSalt(byteCount: number): string {
  return crypto.Random.getRandomBuffer(byteCount).toString('base64')
}
