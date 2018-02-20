const should = require('should')
const Keystore = require('../index')
const keystore = new Keystore()

const password = 'JHJ23jG^*DGHj667s'
const newPassword = 'Tw5E^g7djfd(29j'
const invalidPassword = 'wrOng pa$$w0rd'
const name = 'address wallet'
const anotherWalletName = 'another address wallet'
const updatedWalletName = 'updated address wallet'
const walletIdLength = 36
const addressLength = 42
const privateKeyLength = 66
const wrongWalletId = 'some_wrong_id'

const privateKeyAddressPair = {
  privateKey: '0xa7fcb4efc392d2c8983cbfe64063f994f85120e60843407af95907d905d0dc9f',
  address: '0xb5C99109DEd6212F667b9467a42DAD1F195cDBa9',
}

let walletId

describe('address wallet', function() {
  this.timeout(20000)

  it('createWallet() should throw error (password is weak)', function(done) {
    try {
      keystore.createWallet({
        name,
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

  it('createWallet() should create wallet and return id of it', function(done) {
    walletId = keystore.createWallet({
      name,
      password,
      type: 'address',
      privateKey: privateKeyAddressPair.privateKey,
    })

    walletId.should.be.a.String()
    walletId.length.should.be.equal(walletIdLength)

    done()
  })

  it('createWallet() [READ ONLY] should throw error (wallet with this address exists)',
    function(done) {
      try {
        keystore.createWallet({
          password,
          type: 'address',
          isReadOnly: true,
          address: privateKeyAddressPair.address,
        })

        done(new Error('Exception not thrown'))
      } catch (e) {
        e.should.be.an.Object()
        e.message.should.be.equal('Wallet with this address already exists')

        done()
      }
    }
  )

  it('createWallet() should throw error (privateKey is invalid)', function(done) {
    try {
      keystore.createWallet({
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

  it('setWalletName() should throw error (empty new name)', function(done) {
    try {
      keystore.setWalletName(walletId, '')

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('New wallet name should not be empty')

      done()
    }
  })

  it('setWalletName() should throw error (for not existed wallet)', function(done) {
    try {
      keystore.setWalletName(wrongWalletId, '123')

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal(`Wallet with id ${wrongWalletId} not found`)

      done()
    }
  })

  it('setWalletName() should throw error (if name is the same)', function(done) {
    try {
      keystore.setWalletName(walletId, name)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('New wallet name should not be equal with the old one')

      done()
    }
  })

  it('setWalletName() should throw error (wallet with this name exists)', function(done) {
    const anotherWalletId = keystore.createWallet({
      password,
      type: 'address',
      name: anotherWalletName,
      privateKey: `0x${'1'.repeat(64)}`,
    })

    try {
      keystore.setWalletName(walletId, anotherWalletName)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet with this name already exists')

      done()
    }
  })

  it('setWalletName() should update wallet name', function(done) {
    const wallet = keystore.setWalletName(walletId, updatedWalletName)

    wallet.id.should.be.equal(walletId)
    wallet.name.should.be.equal(updatedWalletName)

    done()
  })

  it('getWallet() should return updated wallet', function(done) {
    const wallet = keystore.getWallet(walletId)

    wallet.id.should.be.equal(walletId)
    wallet.name.should.be.equal(updatedWalletName)

    done()
  })

  it('getAddress() should get current address', function(done) {
    const walletAddress = keystore.getAddress(walletId)

    walletAddress.should.be.a.String()
    walletAddress.length.should.be.equal(addressLength)
    walletAddress.should.be.equal(privateKeyAddressPair.address)

    done()
  })

  it('setPassword() should change keystore password', function(done) {
    keystore.setPassword(password, newPassword, walletId)

    done()
  })

  it('getPrivateKey() should get current private key', function(done) {
    const walletPrivateKey = keystore.getPrivateKey(newPassword, walletId)

    walletPrivateKey.should.be.a.String()
    walletPrivateKey.length.should.be.equal(privateKeyLength)
    walletPrivateKey.should.be.equal(privateKeyAddressPair.privateKey)

    done()
  })

  it('getDecryptedWallet() should get current private key', function(done) {
    const decryptedWallet = keystore.getDecryptedWallet(newPassword, walletId)

    decryptedWallet.should.be.an.Object()
    decryptedWallet.name.should.be.equal(updatedWalletName)
    decryptedWallet.privateKey.should.be.equal(privateKeyAddressPair.privateKey)

    done()
  })

  it('removeWallets() should remove all wallets', function(done) {
    keystore.removeWallets()

    const wallets = keystore.getWallets()

    wallets.should.be.an.Array()
    wallets.length.should.be.equal(0)

    done()
  })
})
