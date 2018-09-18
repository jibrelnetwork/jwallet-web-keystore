// @flow

import Mnemonic from 'bitcore-mnemonic'
import { crypto } from 'bitcore-lib'

const DEFAULT_RANDOM_BUFFER_LENGTH: number = 32
const BIP32_EXTENDABLE_PUBLIC_KEY_LENGTH: number = 111
const ENGLISH_WORDS: Array<string> = Mnemonic.Words.ENGLISH

function concatEntropyBuffers(entropyBuffer: Buffer, randomBuffer: Buffer): Buffer {
  const totalEntropy: Buffer = Buffer.concat([entropyBuffer, randomBuffer])

  if (totalEntropy.length !== (entropyBuffer.length + randomBuffer.length)) {
    throw new Error('Concatenation of entropy buffers failed.')
  }

  return crypto.Hash.sha256(totalEntropy)
}

function getHashedEntropy(entropy: ?string, randomBufferLength: number): ?Buffer {
  if (!entropy) {
    return null
  } else if (typeof entropy !== 'string') {
    throw new TypeError('Entropy is set but not a string.')
  }

  const entropyBuffer: Buffer = Buffer.from(entropy)
  const randomBuffer: Buffer = crypto.Random.getRandomBuffer(randomBufferLength)

  return concatEntropyBuffers(entropyBuffer, randomBuffer).slice(0, 16)
}

export function generateMnemonic(
  entropy?: string,
  randomBufferLength?: number = DEFAULT_RANDOM_BUFFER_LENGTH,
): string {
  const hashedEntropy: ?Buffer = getHashedEntropy(entropy, randomBufferLength)

  const mnemonic = hashedEntropy
    ? new Mnemonic(hashedEntropy, ENGLISH_WORDS)
    : new Mnemonic(ENGLISH_WORDS)

  return mnemonic.toString()
}

export function checkMnemonicValid(mnemonic: string): boolean {
  return Mnemonic.isValid(mnemonic, ENGLISH_WORDS)
}

export function checkBip32XPublicKeyValid(bip32XPublicKey: string): boolean {
  if (!bip32XPublicKey || (bip32XPublicKey.length !== BIP32_EXTENDABLE_PUBLIC_KEY_LENGTH)) {
    return false
  }

  const reLengthWithoutXPUB: number = BIP32_EXTENDABLE_PUBLIC_KEY_LENGTH - 4
  const re: RegExp = new RegExp(`^(xpub)([A-Z\\d]{${reLengthWithoutXPUB}})$`, 'i')

  return re.test(bip32XPublicKey)
}
