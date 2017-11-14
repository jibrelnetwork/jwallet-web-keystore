const should = require('should')
const Keystore = require('../index')
const keystore = new Keystore()

const password = 'JHJ23jG^*DGHj667s'
const newPassword = 'Tw5E^g7djfd(29j'
const accountName = 'address account'
const anotherAccountName = 'another address account'
const updatedAccountName = 'updated address account'
const accountIdLength = 36
const addressLength = 42
const privateKeyLength = 66

const privateKeyAddressPair = {
  privateKey: '0xa7fcb4efc392d2c8983cbfe64063f994f85120e60843407af95907d905d0dc9f',
  address: '0xb5c99109ded6212f667b9467a42dad1f195cdba9',
}

let accountId

describe('address account', function() {
  this.timeout(20000)

  it('createAccount() should throw error (password is weak)', function(done) {
    try {
      keystore.createAccount({
        accountName,
        type: 'address',
        password: 'some weak password',
        privateKey: privateKeyAddressPair.privateKey,
      })

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('The password must contain at least one uppercase letter')

      done()
    }
  })

  it('createAccount() should create account and return id of it', function(done) {
    accountId = keystore.createAccount({
      password,
      accountName,
      type: 'address',
      privateKey: privateKeyAddressPair.privateKey,
    })

    accountId.should.be.a.String()
    accountId.length.should.be.equal(accountIdLength)

    done()
  })

  it('createAccount() [READ ONLY] should throw error (account with this address exists)', function(done) {
    try {
      keystore.createAccount({
        password,
        type: 'address',
        isReadOnly: true,
        address: privateKeyAddressPair.address,
      })

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Account with this address already exists')

      done()
    }
  })

  it('createAccount() should throw error (privateKey is invalid)', function(done) {
    try {
      keystore.createAccount({
        password,
        type: 'address',
        privateKey: 'qwert',
      })

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Private Key is invalid')

      done()
    }
  })

  it('setAccountName() should throw error (empty new name)', function(done) {
    try {
      keystore.setAccountName(accountId, '')

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('New account name should be not empty')

      done()
    }
  })

  it('setAccountName() should throw error (for not existed account)', function(done) {
    try {
      keystore.setAccountName('some_wrong_id')

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Account not found')

      done()
    }
  })

  it('setAccountName() should return unchanged account if accountName is the same', function(done) {
    const sameAccount = keystore.setAccountName(accountId, accountName)

    sameAccount.id.should.be.equal(accountId)
    sameAccount.accountName.should.be.equal(accountName)

    done()
  })

  it('setAccountName() should throw error (account with this name exists)', function(done) {
    const anotherAccountId = keystore.createAccount({
      password,
      accountName: anotherAccountName,
      type: 'address',
      privateKey: `0x${'1'.repeat(64)}`,
    })

    try {
      keystore.setAccountName(accountId, anotherAccountName)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Account with this name already exists')

      done()
    }
  })

  it('setAccountName() should update account name', function(done) {
    const account = keystore.setAccountName(accountId, updatedAccountName)

    account.id.should.be.equal(accountId)
    account.accountName.should.be.equal(updatedAccountName)

    done()
  })

  it('getAccount() should return updated account', function(done) {
    const account = keystore.getAccount({ id: accountId })

    account.id.should.be.equal(accountId)
    account.accountName.should.be.equal(updatedAccountName)

    done()
  })

  it('setPassword() should change keystore password', function(done) {
    keystore.setPassword(password, newPassword)

    done()
  })

  it('getPrivateKey() should get current private key', function(done) {
    const currentPrivateKey = keystore.getPrivateKey(newPassword, accountId)

    currentPrivateKey.should.be.a.String()
    currentPrivateKey.length.should.be.equal(privateKeyLength)
    currentPrivateKey.should.be.equal(privateKeyAddressPair.privateKey)

    done()
  })

  it('getDecryptedAccounts() should get current private key', function(done) {
    const decryptedAccounts = keystore.getDecryptedAccounts(newPassword)

    decryptedAccounts.should.be.an.Array()
    decryptedAccounts.length.should.be.equal(2)
    decryptedAccounts[0].accountName.should.be.equal(updatedAccountName)
    decryptedAccounts[0].privateKey.should.be.equal(privateKeyAddressPair.privateKey)

    done()
  })

  it('removeAccounts() should remove all accounts', function(done) {
    keystore.removeAccounts(newPassword)

    const accounts = keystore.getAccounts()

    accounts.should.be.an.Array()
    accounts.length.should.be.equal(0)

    done()
  })
})
