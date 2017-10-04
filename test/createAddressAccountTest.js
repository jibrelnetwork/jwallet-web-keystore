const should = require('should')
const Keystore = require('../index')
const keystore = new Keystore()

const password = 'JHJ23jG^*DGHj667s'
const newPassword = 'Tw5E^g7djfd(29j'
const accountName = 'address account'
const updatedAccountName = 'updated address account'
const privateKey = `0x${'1'.repeat(64)}`
const accountIdLength = 36
const addressLength = 42
const privateKeyLength = 66

let accountId

describe('address account', function() {
  this.timeout(20000)

  it('createAccount() should throw error (password is weak)', function(done) {
    try {
      keystore.createAccount({
        privateKey,
        accountName,
        type: 'address',
        password: 'some weak password',
      })

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Password is too weak')

      done()
    }
  })

  it('createAccount() should create account and return id of it', function(done) {
    accountId = keystore.createAccount({
      password,
      privateKey,
      accountName,
      type: 'address',
    })

    accountId.should.be.a.String()
    accountId.length.should.be.equal(accountIdLength)

    done()
  })

  it('createAccount() should throw error (privateKey is invalid)', function(done) {
    try {
      keystore.createAccount({
        password,
        accountName,
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
    currentPrivateKey.should.be.equal(privateKey)

    done()
  })

  it('getDecryptedAccounts() should get current private key', function(done) {
    const decryptedAccounts = keystore.getDecryptedAccounts(newPassword)

    decryptedAccounts.should.be.an.Array()
    decryptedAccounts.length.should.be.equal(1)
    decryptedAccounts[0].accountName.should.be.equal(updatedAccountName)
    decryptedAccounts[0].privateKey.should.be.equal(privateKey)

    done()
  })

  it('removeAccounts() should remove all accounts', function(done) {
    keystore.removeAccounts()

    const accounts = keystore.getAccounts()

    accounts.should.be.an.Array()
    accounts.length.should.be.equal(0)

    done()
  })
})
