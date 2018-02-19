const should = require('should')
const Keystore = require('../index')
const keystore = new Keystore()

const password = 'JHJ23jG^*DGHj667s'
const bip32XPublicKey = 'xpub6DZVENYSZsMW1D48vLG924qPaxz83TZc43tK7zMbCdFcv1La9pqe6pBiuxdzDNjufXRW42CfJEK8indRdhfDoWvYfZDZS1xjkZrQB5iYtHy'
const walletName = 'mnemonic read only wallet'
const addressesCountToDerive = 5
const customAddressesCountToDerive = 10
const walletIdLength = 36
const addressLength = 42

let walletId
let firstDerivedAddress

describe('mnemonic read only wallet', function() {
  this.timeout(20000)

  it('createWallet() should create wallet and return id of it', function(done) {
    walletId = keystore.createWallet({
      password,
      walletName,
      bip32XPublicKey,
      type: 'mnemonic',
      isReadOnly: true,
    })

    walletId.should.be.a.String()
    walletId.length.should.be.equal(walletIdLength)

    done()
  })

  it('createWallet() should throw error (bip32XPublicKey is invalid)', function(done) {
    try {
      keystore.createWallet({
        password,
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

  it('getWallet() should return created wallet', function(done) {
    const wallet = keystore.getWallet({ id: walletId })

    wallet.id.should.be.equal(walletId)
    wallet.walletName.should.be.equal(walletName)
    wallet.bip32XPublicKey.should.be.equal(bip32XPublicKey)

    done()
  })

  it('getAddressesFromMnemonic() should derive addresses from mnemonic with default path', function(done) {
    const addresses = keystore.getAddressesFromMnemonic(walletId, 0, customAddressesCountToDerive)

    addresses.should.be.an.Array()
    addresses.length.should.be.equal(customAddressesCountToDerive)

    firstDerivedAddress = addresses[0]

    firstDerivedAddress.should.be.a.String()
    firstDerivedAddress.length.should.be.equal(addressLength)

    done()
  })

  it('getAddressFromMnemonic() should derive address by index from mnemonic', function(done) {
    const address = keystore.getAddressFromMnemonic(walletId, 0)

    address.should.be.a.String()
    address.length.should.be.equal(addressLength)

    done()
  })

  it('setAddressIndex() should set current address index', function(done) {
    const addressIndex = 3
    const wallet = keystore.setAddressIndex(walletId, addressIndex)

    wallet.should.be.an.Object()
    wallet.id.should.be.equal(walletId)
    wallet.addressIndex.should.be.a.Number()
    wallet.addressIndex.should.be.equal(addressIndex)

    done()
  })

  it('getMnemonic() should throw error (wallet is read only)', function(done) {
    try {
      keystore.getMnemonic(password, walletId)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet is read only')

      done()
    }
  })

  it('removeWallet() should return false (incorrect walletId)', function(done) {
    const result = keystore.removeWallet('')
    const wallets = keystore.getWallets()

    result.should.be.a.Boolean()
    result.should.be.equal(false)

    wallets.should.be.an.Array()
    wallets.length.should.be.equal(1)

    done()
  })

  it('removeWallet() should return true', function(done) {
    const result = keystore.removeWallet(walletId)
    const wallets = keystore.getWallets()

    result.should.be.a.Boolean()
    result.should.be.equal(true)

    wallets.should.be.an.Array()
    wallets.length.should.be.equal(0)

    done()
  })
})
