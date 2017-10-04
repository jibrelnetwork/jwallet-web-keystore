const should = require('should')
const Keystore = require('../index')
const keystore = new Keystore()

const password = 'JHJ23jG^*DGHj667s'
const mnemonic = Keystore.generateMnemonic().toString()
const accountName = 'mnemonic account'
const customDerivationPath = "m/44'/61'/0'/0"
const mnemonicWordsCount = 12
const addressesCountToDerive = 5
const accountIdLength = 36
const addressLength = 42
const privateKeyLength = 66

let accountId
let firstDerivedAddress

describe('mnemonic account', function() {
  this.timeout(20000)

  it('createAccount() should create account and return id of it', function(done) {
    accountId = keystore.createAccount({
      password,
      mnemonic,
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
        accountName,
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
    settedMnemonic.should.be.equal(mnemonic)

    done()
  })

  it('getAddressesFromMnemonic() should derive addresses from mnemonic with default path', function(done) {
    const addresses = keystore.getAddressesFromMnemonic(password, accountId)

    addresses.should.be.an.Array()
    addresses.length.should.be.equal(addressesCountToDerive)

    firstDerivedAddress = addresses[0]

    firstDerivedAddress.should.be.a.String()
    firstDerivedAddress.length.should.be.equal(addressLength)

    done()
  })

  it('setDerivationPath() should throw error (derivation path is empty)', function(done) {
    try {
      keystore.setDerivationPath(password, accountId)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('New derivation path should be not empty')

      done()
    }
  })

  it('setDerivationPath() should set custom derivation path', function(done) {
    const account = keystore.setDerivationPath(password, accountId, customDerivationPath)

    account.should.be.an.Object()
    account.id.should.be.equal(accountId)
    account.derivationPath.should.be.equal(customDerivationPath)

    done()
  })

  it('getAddressesFromMnemonic() should derive addresses from mnemonic with custom path', function(done) {
    const addresses = keystore.getAddressesFromMnemonic(password, accountId)

    addresses.should.be.an.Array()
    addresses.length.should.be.equal(addressesCountToDerive)

    const firstDerivedAddressWithCustomPath = addresses[0]

    firstDerivedAddressWithCustomPath.should.be.a.String()
    firstDerivedAddressWithCustomPath.length.should.be.equal(addressLength)
    firstDerivedAddressWithCustomPath.should.not.be.equal(firstDerivedAddress)

    done()
  })

  it('getPrivateKey() should throw error (address not setted yet)', function(done) {
    try {
      keystore.getPrivateKey(password, accountId)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Address is not setted yet')

      done()
    }
  })

  it('setAddress() should set current address derived from mnemonic by index', function(done) {
    const account = keystore.setAddress(password, accountId, 3)

    account.should.be.an.Object()
    account.id.should.be.equal(accountId)
    account.address.should.be.a.String()
    account.address.length.should.be.equal(addressLength)

    done()
  })

  it('getPrivateKey() should get current private key', function(done) {
    const privateKey = keystore.getPrivateKey(password, accountId)

    privateKey.should.be.a.String()
    privateKey.length.should.be.equal(privateKeyLength)

    done()
  })
})
