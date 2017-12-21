const Mnemonic = require('bitcore-mnemonic')
const bitcore = require('bitcore-lib')

const { Random, Hash } = bitcore.crypto

const BIP32_EXTENDABLE_PUBLIC_KEY_LENGTH = 111

function generateMnemonic(entropy, randomBufferLength) {
  const dataList = Mnemonic.Words.ENGLISH
  const hashedEntropy = getHashedEntropy(entropy, randomBufferLength)

  const mnemonic = hashedEntropy ? new Mnemonic(hashedEntropy, dataList) : new Mnemonic(dataList)

  return mnemonic
}

function isMnemonicValid(mnemonic) {
  return Mnemonic.isValid(mnemonic, Mnemonic.Words.ENGLISH)
}

function isBip32XPublicKeyValid(bip32XPublicKey) {
  if (!bip32XPublicKey || (bip32XPublicKey.length !== BIP32_EXTENDABLE_PUBLIC_KEY_LENGTH)) {
    return false
  }

  const re = new RegExp(`^(xpub)([A-Z\\d]{${BIP32_EXTENDABLE_PUBLIC_KEY_LENGTH - 4}})$`, 'i')

  return re.test(bip32XPublicKey)
}

function getHashedEntropy(entropy, randomBufferLength) {
  if (!entropy) {
    return null
  } else if (typeof entropy !== 'string') {
    throw (new Error('Entropy is set but not a string.'))
  }

  const entropyBuffer = Buffer.from(entropy)
  const randomBuffer = Random.getRandomBuffer(randomBufferLength)

  return concatEntropyBuffers(entropyBuffer, randomBuffer).slice(0, 16)
}

function concatEntropyBuffers(entropyBuffer, randomBuffer) {
  const totalEntropy = Buffer.concat([entropyBuffer, randomBuffer])

  if (totalEntropy.length !== entropyBuffer.length + randomBuffer.length) {
    throw (new Error('Concatenation of entropy buffers failed.'))
  }

  return Hash.sha256(totalEntropy)
}

module.exports = { generateMnemonic, isMnemonicValid, isBip32XPublicKeyValid }
