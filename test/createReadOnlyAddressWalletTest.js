const should = require('should')
const Keystore = require('../index')
const keystore = new Keystore()

const password = 'JHJ23jG^*DGHj667s'
const name = 'address read only wallet'
const walletIdLength = 36
const addressLength = 42

const privateKeyAddressPair = {
  privateKey: '0xa7fcb4efc392d2c8983cbfe64063f994f85120e60843407af95907d905d0dc9f',
  address: '0xb5c99109ded6212f667b9467a42dad1f195cdba9',
}

let walletId

describe('address read only wallet', function() {
  this.timeout(20000)

  it('createWallet() should create wallet and return id of it', function(done) {
    walletId = keystore.createWallet({
      name,
      password,
      type: 'address',
      isReadOnly: true,
      address: privateKeyAddressPair.address,
    })

    walletId.should.be.a.String()
    walletId.length.should.be.equal(walletIdLength)

    done()
  })

  it('createWallet() [FULL ACCESS] should throw error (wallet with this address exists)', function(done) {
    try {
      keystore.createWallet({
        password,
        type: 'address',
        isReadOnly: false,
        privateKey: privateKeyAddressPair.privateKey,
      })

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet with this address already exists')

      done()
    }
  })

  it('createWallet() should throw error (wallet with this name exists)', function(done) {
    try {
      keystore.createWallet({
        name,
        password,
        type: 'address',
        isReadOnly: true,
        address: privateKeyAddressPair.address,
      })

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet with this name already exists')

      done()
    }
  })

  it('createWallet() should throw error (address is invalid)', function(done) {
    try {
      keystore.createWallet({
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

  it('createWallet() should throw error (invalid type of wallet)', function(done) {
    try {
      keystore.createWallet({
        password,
        type: 'qwert',
        isReadOnly: true,
        address: privateKeyAddressPair.address,
      })

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Type of wallet not provided or invalid')

      done()
    }
  })

  it('createWallet() should throw error (type not provided)', function(done) {
    try {
      keystore.createWallet({
        password,
        isReadOnly: true,
        address: privateKeyAddressPair.address,
      })

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Type of wallet not provided or invalid')

      done()
    }
  })

  it('createWallet() should throw error (invalid password)', function(done) {
    try {
      keystore.createWallet({
        isReadOnly: true,
        password: 'some_wrong_password',
        address: privateKeyAddressPair.address,
      })

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('The password must contain at least one uppercase letter')

      done()
    }
  })

  it('getMnemonic() should throw error (wrong type)', function(done) {
    try {
      keystore.getMnemonic(password, walletId)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet type is not mnemonic')

      done()
    }
  })

  it('getWallet() should return created wallet', function(done) {
    const wallet = keystore.getWallet(walletId)

    wallet.id.should.be.equal(walletId)
    wallet.name.should.be.equal(name)
    wallet.address.should.be.equal(privateKeyAddressPair.address)
    wallet.address.length.should.be.equal(addressLength)

    done()
  })

  it('getWallet() should throw error (without wallet id)', function(done) {
    try {
      keystore.getWallet()

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet ID not provided')

      done()
    }
  })

  it('getPrivateKey() should throw error (for read only wallet)', function(done) {
    try {
      keystore.getPrivateKey(password, walletId)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet is read only')

      done()
    }
  })

  it('getDecryptedWallet() should return wallet data', function(done) {
    const wallet = keystore.getDecryptedWallet(password, walletId)

    wallet.should.be.an.Object()
    wallet.name.should.be.equal(name)
    wallet.id.should.be.equal(walletId)
    wallet.readOnly.should.be.equal('yes')
    wallet.type.should.be.equal('address')
    wallet.address.should.be.equal(privateKeyAddressPair.address)

    done()
  })
})
