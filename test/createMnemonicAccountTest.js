const should = require('should')
const Keystore = require('../index')
const keystore = new Keystore()

const password = 'JHJ23jG^*DGHj667s'
const accountName = 'mnemonic account'
const derivationPath = "m/44'/60'/0'/0"
const customDerivationPath = "m/44'/60'/1'/0"
const customDerivationPath2 = "m/44'/60'/2'/0"
const mnemonicWordsCount = 12
const addressesCountToDerive = 5
const accountIdLength = 36
const addressLength = 42
const privateKeyLength = 66
const addressIndex = 3

const mnemonicXPubPair = {
  mnemonic: 'sunny boil orient spawn edit voyage impose eager notice parent boat pudding',
  bip32XPublicKey: 'xpub6ENQhtq6UZ7CVznP3uC8mkb9FAfuMepKMdeaBiBoRZwUjZkoYgoXztnggqTfd7DkC8tTZsN5RSPh7Wme42PF8sSRSSCqqdg381zbu2QMEHc',
  bip32XPublicKeyCustomPath: 'xpub6EHUjFfkAkfqXkqkcZKNxa4Gx6ybxSfRFFeUYsBsqm2Eg2xrz7KWtAmW1pdJ6DNA852xkLtCPTbCinawRFm29WD4XLF8npKNQNpYa42cCwy',
}

let accountId
let firstDerivedAddress

describe('mnemonic account', function() {
  this.timeout(20000)

  it('createAccount() should create account and return id of it', function(done) {
    accountId = keystore.createAccount({
      password,
      mnemonic: mnemonicXPubPair.mnemonic,
      accountName,
      type: 'mnemonic',
      isReadOnly: false,
    })

    accountId.should.be.a.String()
    accountId.length.should.be.equal(accountIdLength)

    done()
  })

  it('createAccount() should throw error (mnemonic is invalid)', function(done) {
    try {
      keystore.createAccount({
        password,
        type: 'mnemonic',
        mnemonic: 'some wrong mnemonic',
      })

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Invalid mnemonic')

      done()
    }
  })

  it('createAccount() should throw error (account with this xpub exists)', function(done) {
    try {
      keystore.createAccount({
        password,
        mnemonic: mnemonicXPubPair.mnemonic,
        type: 'mnemonic',
      })

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Account with this xpub already exists')

      done()
    }
  })

  it('createAccount() [READ ONLY] should throw error (account with this xpub exists)', function(done) {
    try {
      keystore.createAccount({
        password,
        bip32XPublicKey: mnemonicXPubPair.bip32XPublicKey,
        type: 'mnemonic',
        isReadOnly: true,
      })

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Account with this xpub already exists')

      done()
    }
  })

  it('getAccounts() should return accounts list with one item', function(done) {
    const accounts = keystore.getAccounts()

    accounts.should.be.an.Array()
    accounts.length.should.be.equal(1)
    accounts[0].id.should.be.equal(accountId)
    accounts[0].accountName.should.be.equal(accountName)

    done()
  })

  it('getMnemonic() should get setted mnemonic', function(done) {
    const settedMnemonic = keystore.getMnemonic(password, accountId)
    const words = settedMnemonic.split(' ')

    settedMnemonic.should.be.a.String()
    settedMnemonic.length.should.be.greaterThan(0)
    words.length.should.be.equal(mnemonicWordsCount)
    settedMnemonic.should.be.equal(mnemonicXPubPair.mnemonic)

    done()
  })

  it('getAddressesFromMnemonic() should derive addresses from mnemonic with default path', function(done) {
    const addresses = keystore.getAddressesFromMnemonic(accountId)

    addresses.should.be.an.Array()
    addresses.length.should.be.equal(addressesCountToDerive)

    firstDerivedAddress = addresses[0]

    firstDerivedAddress.should.be.a.String()
    firstDerivedAddress.length.should.be.equal(addressLength)

    done()
  })

  it('setDerivationPath() should throw error (derivation path is invalid)', function(done) {
    try {
      keystore.setDerivationPath(password, accountId)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Invalid derivation path')

      done()
    }
  })

  it('setDerivationPath() should throw error (same derivation path)', function(done) {
    try {
      keystore.setDerivationPath(password, accountId, derivationPath)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Can not set the same derivation path')

      done()
    }
  })

  it('setDerivationPath() should throw error (account with this xpub exists)', function(done) {
    try {
      /**
       * This account will have the same bip32XPublicKey as the account,
       * that was created before with setted customDerivationPath
       * so exception will thrown
       */
      const newId = keystore.createAccount({
        password,
        bip32XPublicKey: mnemonicXPubPair.bip32XPublicKeyCustomPath,
        type: 'mnemonic',
        isReadOnly: true,
      })

      keystore.setDerivationPath(password, accountId, customDerivationPath)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Account with this xpub already exists')

      done()
    }
  })

  it('setDerivationPath() should set custom derivation path', function(done) {
    const account = keystore.setDerivationPath(password, accountId, customDerivationPath2)

    account.should.be.an.Object()
    account.id.should.be.equal(accountId)
    account.derivationPath.should.be.equal(customDerivationPath2)

    done()
  })

  it('getAddressesFromMnemonic() should derive addresses from mnemonic with custom path', function(done) {
    const addresses = keystore.getAddressesFromMnemonic(accountId)

    addresses.should.be.an.Array()
    addresses.length.should.be.equal(addressesCountToDerive)

    const firstDerivedAddressWithCustomPath = addresses[0]

    firstDerivedAddressWithCustomPath.should.be.a.String()
    firstDerivedAddressWithCustomPath.length.should.be.equal(addressLength)
    firstDerivedAddressWithCustomPath.should.not.be.equal(firstDerivedAddress)

    done()
  })

  it('setAddressIndex() should set current address index', function(done) {
    const account = keystore.setAddressIndex(accountId, addressIndex)

    account.should.be.an.Object()
    account.id.should.be.equal(accountId)
    account.addressIndex.should.be.a.Number()
    account.addressIndex.should.be.equal(addressIndex)

    done()
  })

  it('getPrivateKey() should get private key by index', function(done) {
    const privateKey = keystore.getPrivateKey(password, accountId, addressIndex)

    privateKey.should.be.a.String()
    privateKey.length.should.be.equal(privateKeyLength)

    done()
  })
})
