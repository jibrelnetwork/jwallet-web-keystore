const should = require('should')
const Keystore = require('../index')
const keystore = new Keystore()

const password = 'JHJ23jG^*DGHj667s'
const accountName = 'address read only account'
const accountIdLength = 36
const addressLength = 42

const privateKeyAddressPair = {
  privateKey: '0xa7fcb4efc392d2c8983cbfe64063f994f85120e60843407af95907d905d0dc9f',
  address: '0xb5c99109ded6212f667b9467a42dad1f195cdba9',
}

let accountId

describe('address read only account', function() {
  this.timeout(20000)

  it('createAccount() should create account and return id of it', function(done) {
    accountId = keystore.createAccount({
      password,
      accountName,
      type: 'address',
      isReadOnly: true,
      address: privateKeyAddressPair.address,
    })

    accountId.should.be.a.String()
    accountId.length.should.be.equal(accountIdLength)

    done()
  })

  it('createAccount() [FULL ACCESS] should throw error (account with this address exists)', function(done) {
    try {
      keystore.createAccount({
        password,
        type: 'address',
        isReadOnly: false,
        privateKey: privateKeyAddressPair.privateKey,
      })

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Account with this address already exists')

      done()
    }
  })

  it('createAccount() should throw error (account with this name exists)', function(done) {
    try {
      keystore.createAccount({
        password,
        accountName,
        type: 'address',
        isReadOnly: true,
        address: privateKeyAddressPair.address,
      })

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Account with this name already exists')

      done()
    }
  })

  it('createAccount() should throw error (address is invalid)', function(done) {
    try {
      keystore.createAccount({
        password,
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
        type: 'qwert',
        isReadOnly: true,
        address: privateKeyAddressPair.address,
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
        isReadOnly: true,
        address: privateKeyAddressPair.address,
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
        isReadOnly: true,
        password: 'some_wrong_password',
        address: privateKeyAddressPair.address,
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
    account.address.should.be.equal(privateKeyAddressPair.address)
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
