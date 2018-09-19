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

const mnemonicWordsCount = 12

describe('utils methods test', () => {
  it('testPassword() should return failed/passed tests count and errors if any', (done) => {
    const testPasswordResult = keystore.testPassword(password)
    const testPasswordResultInvalid = keystore.testPassword(passwordInvalid)

    testPasswordResult.should.be.an.Object()
    testPasswordResult.score.should.be.equal(3)
    testPasswordResult.feedback.warning.should.be.equal('')
    testPasswordResult.feedback.suggestions.should.be.an.Array()
    testPasswordResult.feedback.suggestions.length.should.be.equal(0)

    testPasswordResultInvalid.should.be.an.Object()
    testPasswordResultInvalid.score.should.be.equal(0)
    testPasswordResultInvalid.feedback.suggestions.should.be.an.Array()
    testPasswordResultInvalid.feedback.suggestions.length.should.be.greaterThan(0)
    testPasswordResultInvalid.feedback.suggestions[0].should.be.a.String()
    testPasswordResultInvalid.feedback.suggestions[0].length.should.be.greaterThan(0)
    testPasswordResultInvalid.feedback.warning.should.be.equal('This is a top-10 common password')

    done()
  })

  it('generateMnemonic() should generate 12 random English words', (done) => {
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

  it('checkMnemonicValid() should return true when Mnemonic is valid', (done) => {
    const isMnemonicValidA = keystore.checkMnemonicValid(mnemonic)
    const isMnemonicValidB = keystore.checkMnemonicValid(mnemonicInvalid)

    isMnemonicValidA.should.be.a.Boolean()
    isMnemonicValidA.should.be.equal(true)

    isMnemonicValidB.should.be.a.Boolean()
    isMnemonicValidB.should.be.equal(false)

    done()
  })

  it('checkBip32XPublicKeyValid() should return true when xpub key is valid', (done) => {
    const isXPubValidA = keystore.checkBip32XPublicKeyValid(bip32XPubKey)
    const isXPubValidB = keystore.checkBip32XPublicKeyValid(bip32XPubKeyInvalid)

    isXPubValidA.should.be.a.Boolean()
    isXPubValidA.should.be.equal(true)

    isXPubValidB.should.be.a.Boolean()
    isXPubValidB.should.be.equal(false)

    done()
  })

  it('checkAddressValid() should return true when address is correct', (done) => {
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

  it('checkPrivateKeyValid() should return true when private key is correct', (done) => {
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

  it('checkDerivationPathValid() should return true when xpub key is valid', (done) => {
    const isDerivationPathValidA = keystore.checkDerivationPathValid(derivationPath)
    const isDerivationPathValidB = keystore.checkDerivationPathValid(derivationPathInvalid)

    isDerivationPathValidA.should.be.a.Boolean()
    isDerivationPathValidA.should.be.equal(true)

    isDerivationPathValidB.should.be.a.Boolean()
    isDerivationPathValidB.should.be.equal(false)

    done()
  })
})
