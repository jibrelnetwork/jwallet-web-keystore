const should = require('should')
const Keystore = require('../index')
const keystore = new Keystore()

const password = 'JHJ23jG^*DGHj667s'
const bip32XPublicKey = 'xpub6DZVENYSZsMW1D48vLG924qPaxz83TZc43tK7zMbCdFcv1La9pqe6pBiuxdzDNjufXRW42CfJEK8indRdhfDoWvYfZDZS1xjkZrQB5iYtHy'
const accountName = 'mnemonic read only account'
const addressesCountToDerive = 3
const accountIdLength = 36
const addressLength = 42

let accountId
let firstDerivedAddress

describe('mnemonic read only account', function() {
  this.timeout(20000)

  it('createAccount() should create account and return id of it', function(done) {
    accountId = keystore.createAccount({
      password,
      accountName,
      bip32XPublicKey,
      type: 'mnemonic',
      isReadOnly: true,
    })

    accountId.should.be.a.String()
    accountId.length.should.be.equal(accountIdLength)

    done()
  })

  it('createAccount() should throw error (bip32XPublicKey is invalid)', function(done) {
    try {
      keystore.createAccount({
        password,
        accountName,
        type: 'mnemonic',
        isReadOnly: true,
        bip32XPublicKey: 'some wrong key',
      })

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Invalid bip32XPublicKey')

      done()
    }
  })

  it('getAccount() should return created account', function(done) {
    const account = keystore.getAccount({ id: accountId })

    account.id.should.be.equal(accountId)
    account.accountName.should.be.equal(accountName)
    account.bip32XPublicKey.should.be.equal(bip32XPublicKey)

    done()
  })

  it('getAddressesFromMnemonic() should derive addresses from mnemonic with default path', function(done) {
    const addresses = keystore.getAddressesFromMnemonic(null, accountId)

    addresses.should.be.an.Array()
    addresses.length.should.be.equal(addressesCountToDerive)

    firstDerivedAddress = addresses[0]

    firstDerivedAddress.should.be.a.String()
    firstDerivedAddress.length.should.be.equal(addressLength)

    done()
  })

  it('setAddress() should set current address derived from mnemonic by index', function(done) {
    const account = keystore.setAddress(null, accountId, 3)

    account.should.be.an.Object()
    account.id.should.be.equal(accountId)
    account.address.should.be.a.String()
    account.address.length.should.be.equal(addressLength)

    done()
  })

  it('getMnemonic() should throw error (account is read only)', function(done) {
    try {
      keystore.getMnemonic(password, accountId)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Account is read only')

      done()
    }
  })

  it('removeAccount() should return false (incorrect accountId)', function(done) {
    const result = keystore.removeAccount('')
    const accounts = keystore.getAccounts()

    result.should.be.a.Boolean()
    result.should.be.equal(false)

    accounts.should.be.an.Array()
    accounts.length.should.be.equal(1)

    done()
  })

  it('removeAccount() should return true', function(done) {
    const result = keystore.removeAccount(accountId)
    const accounts = keystore.getAccounts()

    result.should.be.a.Boolean()
    result.should.be.equal(true)

    accounts.should.be.an.Array()
    accounts.length.should.be.equal(0)

    done()
  })
})
