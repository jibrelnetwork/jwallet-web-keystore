const should = require('should')
const Keystore = require('../index')
const keystore = new Keystore()

const password = 'JHJ23jG^*DGHj667s'
const accountName = 'address account'
const updatedAccountName = 'updated address account'
const privateKey = `0x${'1'.repeat(64)}`
const accountIdLength = 36
const addressLength = 42
const privateKeyLength = 66

let accountId

describe('address account', function() {
  this.timeout(20000)

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

  it('setAccountName() should update account name', function(done) {
    const account = keystore.setAccountName(password, accountId, updatedAccountName)

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

  it('getPrivateKey() should get current private key', function(done) {
    const currentPrivateKey = keystore.getPrivateKey(password, accountId)

    currentPrivateKey.should.be.a.String()
    currentPrivateKey.length.should.be.equal(privateKeyLength)
    currentPrivateKey.should.be.equal(privateKey)

    done()
  })
})
