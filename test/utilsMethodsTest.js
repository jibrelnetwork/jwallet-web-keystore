/* eslint-disable-next-line no-unused-vars */
import should from 'should'

import keystore from '../lib'

const mnemonic = 'come average primary sunny profit eager toy pulp struggle hazard tourist round'
const mnemonicInvalid = `${mnemonic} some other words`

const mnemonicEntropy = 'some custom entropy'
const mnemonicBufferLength = 64

const privateKey = '0xa7fcb4efc392d2c8983cbfe64063f994f85120e60843407af95907d905d0dc9f'
const privateKeyInvalidA = privateKey.slice(0, -1)
const privateKeyInvalidB = `${privateKey}%`

const address = '0xb5C99109DEd6212F667b9467a42DAD1F195cDBa9'
const addressChecksum = '0xb5C99109DEd6212F667b9467a42DAD1F195cdba9'
const addressInvalidA = address.slice(0, -1)
const addressInvalidB = `${address}a`

const bip32XPubKey = `xpub${'1'.repeat(107)}`
const bip32XPubKeyInvalid = `${bip32XPubKey}%`

const derivationPath = 'm/44\'/60\'/0\''
const derivationPathInvalid = 'qwert'

const password = 'qwe123RTY$%^'
const passwordInvalid = '111111'

const passwordTestsCount = 7
const passwordConfigCustom = { minLength: 20 }

const mnemonicWordsCount = 12

describe('generateMnemonic', () => {
  it('should generate 12 random English words', (done) => {
    const mnemonicGenerated = keystore.generateMnemonic()
    const mnemonicWithEntropy = keystore.generateMnemonic(mnemonicEntropy)

    const mnemonicWithBufferLength = keystore.generateMnemonic(
      mnemonicEntropy,
      mnemonicBufferLength,
    )

    const words = mnemonicGenerated.split(' ')
    const wordsWithEntropy = mnemonicWithEntropy.split(' ')
    const wordsWithBufferLength = mnemonicWithBufferLength.split(' ')

    mnemonicGenerated.should.be.a.String()
    words.length.should.be.equal(mnemonicWordsCount)

    mnemonicWithEntropy.should.be.a.String()
    wordsWithEntropy.length.should.be.equal(mnemonicWordsCount)

    mnemonicWithBufferLength.should.be.a.String()
    wordsWithBufferLength.length.should.be.equal(mnemonicWordsCount)

    done()
  })
})

describe('checkMnemonicValid', () => {
  it('should return true when Mnemonic is valid', (done) => {
    const isMnemonicValidA = keystore.checkMnemonicValid(mnemonic)
    const isMnemonicValidB = keystore.checkMnemonicValid(mnemonicInvalid)

    isMnemonicValidA.should.be.a.Boolean()
    isMnemonicValidA.should.be.equal(true)

    isMnemonicValidB.should.be.a.Boolean()
    isMnemonicValidB.should.be.equal(false)

    done()
  })
})

describe('checkBip32XPublicKeyValid', () => {
  it('should return true when xpub key is valid', (done) => {
    const isXPubValidA = keystore.checkBip32XPublicKeyValid(bip32XPubKey)
    const isXPubValidB = keystore.checkBip32XPublicKeyValid(bip32XPubKeyInvalid)

    isXPubValidA.should.be.a.Boolean()
    isXPubValidA.should.be.equal(true)

    isXPubValidB.should.be.a.Boolean()
    isXPubValidB.should.be.equal(false)

    done()
  })
})

describe('checkAddressValid', () => {
  it('should return true when address is correct', (done) => {
    const isAddressValidA = keystore.checkAddressValid(address)
    const isAddressValidB = keystore.checkAddressValid(addressChecksum)
    const isAddressValidC = keystore.checkAddressValid(addressInvalidA)
    const isAddressValidD = keystore.checkAddressValid(addressInvalidB)

    isAddressValidA.should.be.a.Boolean()
    isAddressValidA.should.be.equal(true)

    isAddressValidB.should.be.a.Boolean()
    isAddressValidB.should.be.equal(false)

    isAddressValidC.should.be.a.Boolean()
    isAddressValidC.should.be.equal(false)

    isAddressValidD.should.be.a.Boolean()
    isAddressValidD.should.be.equal(false)

    done()
  })
})

describe('checkPrivateKeyValid', () => {
  it('should return true when private key is correct', (done) => {
    const isPrivateKeyValidA = keystore.checkPrivateKeyValid(privateKey)
    const isPrivateKeyValidB = keystore.checkPrivateKeyValid(privateKeyInvalidA)
    const isPrivateKeyValidC = keystore.checkPrivateKeyValid(privateKeyInvalidB)

    isPrivateKeyValidA.should.be.a.Boolean()
    isPrivateKeyValidA.should.be.equal(true)

    isPrivateKeyValidB.should.be.a.Boolean()
    isPrivateKeyValidB.should.be.equal(false)

    isPrivateKeyValidC.should.be.a.Boolean()
    isPrivateKeyValidC.should.be.equal(false)

    done()
  })
})

describe('checkDerivationPathValid', () => {
  it('should return true when xpub key is valid', (done) => {
    const isDerivationPathValidA = keystore.checkDerivationPathValid(derivationPath)
    const isDerivationPathValidB = keystore.checkDerivationPathValid(derivationPathInvalid)

    isDerivationPathValidA.should.be.a.Boolean()
    isDerivationPathValidA.should.be.equal(true)

    isDerivationPathValidB.should.be.a.Boolean()
    isDerivationPathValidB.should.be.equal(false)

    done()
  })
})

describe('testPassword', () => {
  it('should return failed/passed tests count and errors if any', (done) => {
    const testPasswordResult = keystore.testPassword(password)
    const testPasswordResultInvalid = keystore.testPassword(passwordInvalid)

    const testPasswordResultWithCustomConfig = keystore.testPassword(
      password,
      passwordConfigCustom,
    )

    testPasswordResult.should.be.an.Object()
    testPasswordResult.failedTests.should.be.an.Array()
    testPasswordResult.failedTests.length.should.be.equal(0)
    testPasswordResult.passedTests.should.be.an.Array()
    testPasswordResult.passedTests.length.should.be.equal(passwordTestsCount)
    testPasswordResult.errors.should.be.an.Array()
    testPasswordResult.errors.length.should.be.equal(0)

    testPasswordResultInvalid.should.be.an.Object()
    testPasswordResultInvalid.failedTests.length.should.be.equal(5)
    testPasswordResultInvalid.passedTests.length.should.be.equal(2)
    testPasswordResultInvalid.errors.length.should.be.equal(5)

    testPasswordResultWithCustomConfig.should.be.an.Object()
    testPasswordResultWithCustomConfig.failedTests.length.should.be.equal(1)
    testPasswordResultWithCustomConfig.passedTests.length.should.be.equal(6)
    testPasswordResultWithCustomConfig.errors.length.should.be.equal(1)
    testPasswordResultWithCustomConfig.errors[0].should.be.equal(
      `The password must be at least ${passwordConfigCustom.minLength} characters long`
    )

    done()
  })
})