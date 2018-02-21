const should = require('should')
const Keystore = require('../index')
const keystore = new Keystore()

const password = 'JHJ23jG^*DGHj667s'
const bip32XPublicKey = 'xpub6DZVENYSZsMW1D48vLG924qPaxz83TZc43tK7zMbCdFcv1La9pqe6pBiuxdzDNjufXRW42CfJEK8indRdhfDoWvYfZDZS1xjkZrQB5iYtHy'
const name = 'mnemonic read only wallet'
const addressesCountToDerive = 5
const customAddressesCountToDerive = 10
const walletIdLength = 36
const addressLength = 42
const incorrectWalletId = 'incorrect'

let walletId
let firstDerivedAddress

describe('mnemonic read only wallet', function() {
  this.timeout(20000)

  it('createWallet() should create wallet and return id of it', function(done) {
    walletId = keystore.createWallet({
      name,
      password,
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
    const wallet = keystore.getWallet(walletId)

    wallet.id.should.be.equal(walletId)
    wallet.name.should.be.equal(name)
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

  it('getAddress() should derive from mnemonic', function(done) {
    const address = keystore.getAddress(walletId)

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

  it('getDecryptedWallet() should return wallet data', function(done) {
    const wallet = keystore.getDecryptedWallet(password, walletId)

    wallet.should.be.an.Object()
    wallet.name.should.be.equal(name)
    wallet.id.should.be.equal(walletId)
    wallet.readOnly.should.be.equal('yes')
    wallet.type.should.be.equal('bip32Xpub')
    wallet.bip32XPublicKey.should.be.equal(bip32XPublicKey)

    done()
  })

  it('removeWallet() should throw error (incorrect walletId)', function(done) {
    try {
      keystore.removeWallet(incorrectWalletId)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal(`Wallet with id ${incorrectWalletId} not found`)

      done()
    }
  })

  it('removeWallet() should return true', function(done) {
    const result = keystore.removeWallet(walletId)
    const wallets = keystore.getWallets()

    result.should.be.an.Object()
    result.id.should.be.equal(walletId)

    wallets.should.be.an.Array()
    wallets.length.should.be.equal(0)

    done()
  })
})
