const should = require('should')
const Keystore = require('../index')
const keystore = new Keystore()

const password = 'JHJ23jG^*DGHj667s'
const accountName = 'address read only account'
const address = `0x${'1'.repeat(40)}`
const accountIdLength = 36
const addressLength = 42

let accountId

describe('address read only account', function() {
  this.timeout(20000)

  it('createAccount() should create account and return id of it', function(done) {
    accountId = keystore.createAccount({
      password,
      address,
      accountName,
      type: 'address',
      isReadOnly: true,
    })

    accountId.should.be.a.String()
    accountId.length.should.be.equal(accountIdLength)

    done()
  })

  it('createAccount() should throw error (address is invalid)', function(done) {
    try {
      keystore.createAccount({
        password,
        accountName,
        type: 'address',
        address: 'qwert',
        isReadOnly: true,
      })

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Address is invalid')

      done()
    }
  })

  it('createAccount() should throw error (invalid type of account)', function(done) {
    try {
      keystore.createAccount({
        password,
        address,
        accountName,
        type: 'qwert',
        isReadOnly: true,
      })

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Type of account not provided or incorrect')

      done()
    }
  })

  it('createAccount() should throw error (type not provided)', function(done) {
    try {
      keystore.createAccount({
        password,
        address,
        accountName,
        isReadOnly: true,
      })

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Type of account not provided or incorrect')

      done()
    }
  })

  it('createAccount() should throw error (incorrect password)', function(done) {
    try {
      keystore.createAccount({
        address,
        accountName,
        isReadOnly: true,
        password: 'some_wrong_password',
      })

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Password is incorrect')

      done()
    }
  })

  it('getAccount() should return created account', function(done) {
    const account = keystore.getAccount({ id: accountId })

    account.id.should.be.equal(accountId)
    account.accountName.should.be.equal(accountName)
    account.address.should.be.equal(address)
    account.address.length.should.be.equal(addressLength)

    done()
  })

  it('getAccount() should throw error (without account id)', function(done) {
    try {
      keystore.getAccount()

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Account ID not provided')

      done()
    }
  })

  it('setAccountName() should throw error (empty new name)', function(done) {
    try {
      keystore.setAccountName(password, accountId, '')

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('New account name should be not empty')

      done()
    }
  })

  it('setAccountName() should throw error (for not existed account)', function(done) {
    try {
      keystore.setAccountName(password, 'some_wrong_id')

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Account not found')

      done()
    }
  })

  it('getPrivateKey() should throw error (for read only account)', function(done) {
    try {
      keystore.getPrivateKey(password, accountId)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Account is read only')

      done()
    }
  })
})
