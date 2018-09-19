/* eslint-disable fp/no-mutating-assign */

/* eslint-disable-next-line no-unused-vars */
import should from 'should'

import keystore from '../lib'

const password = 'JHJ23jG^*DGHj667s'
const name = 'mnemonic read only wallet'
const addressStartIndex = 0
const addressEndIndex = 4
const addressesCountToDerive = 5
const walletIdLength = 36
const addressLength = 42
const incorrectWalletId = 'incorrect'
const walletNameUpdated = 'updated address wallet'

/* eslint-disable-next-line max-len */
const bip32XPublicKey = 'xpub6DZVENYSZsMW1D48vLG924qPaxz83TZc43tK7zMbCdFcv1La9pqe6pBiuxdzDNjufXRW42CfJEK8indRdhfDoWvYfZDZS1xjkZrQB5iYtHy'

const STORE = {
  wallets: [],
  firstDerivedAddress: null,
}

describe('mnemonic read only wallet', function createReadOnlyMnemonicWalletTest() {
  this.timeout(20000)

  it('createWallet() should create wallet and return updated list with it', (done) => {
    const wallets = keystore.createWallet(STORE.wallets, {
      name,
      data: bip32XPublicKey,
    })

    wallets.should.be.an.Array()
    wallets.length.should.be.greaterThan(0)

    // wallet with xpub
    const wallet = wallets[0]

    wallet.should.be.an.Object()
    wallet.id.should.be.a.String()
    wallet.name.should.be.equal(name)
    should(wallet.address).be.equal(null)
    wallet.addressIndex.should.be.equal(0)
    wallet.encrypted.should.be.an.Object()
    wallet.type.should.be.equal('mnemonic')
    wallet.isReadOnly.should.be.equal(true)
    should(wallet.scryptParams).be.equal(null)
    should(wallet.derivationPath).be.equal(null)
    wallet.customType.should.be.equal('bip32Xpub')
    wallet.id.length.should.be.equal(walletIdLength)
    should(wallet.encrypted.mnemonic).be.equal(null)
    should(wallet.encrypted.privateKey).be.equal(null)
    wallet.bip32XPublicKey.should.be.equal(bip32XPublicKey)

    Object.assign(STORE, { wallets })

    done()
  })

  it('getWallet() should return created wallet', (done) => {
    // wallet with xpub
    const wallet = STORE.wallets[0]
    const walletFoundById = keystore.getWallet(STORE.wallets, wallet.id)

    walletFoundById.should.be.an.Object()
    walletFoundById.name.should.be.equal(name)
    walletFoundById.id.should.be.equal(wallet.id)
    walletFoundById.bip32XPublicKey.should.be.equal(bip32XPublicKey)

    done()
  })

  it('setWalletName() should update wallet name', (done) => {
    // wallet with xpub
    const wallet = STORE.wallets[0]
    const wallets = keystore.setWalletName(STORE.wallets, wallet.id, walletNameUpdated)
    const walletWithChangedName = keystore.getWallet(wallets, wallet.id)

    walletWithChangedName.should.be.an.Object()
    walletWithChangedName.id.should.be.equal(wallet.id)
    walletWithChangedName.name.should.be.equal(walletNameUpdated)

    // do not rewrite STORE.wallets to left old name, it will be checked later

    done()
  })

  it('getAddresses() should derive addresses from mnemonic with default path', (done) => {
    // wallet with xpub
    const wallet = STORE.wallets[0]
    const { id } = wallet
    const addresses = keystore.getAddresses(STORE.wallets, id, addressStartIndex, addressEndIndex)

    addresses.should.be.an.Array()
    addresses.length.should.be.equal(addressesCountToDerive)

    const firstDerivedAddress = addresses[0]

    firstDerivedAddress.should.be.a.String()
    firstDerivedAddress.length.should.be.equal(addressLength)

    Object.assign(STORE, { firstDerivedAddress })

    done()
  })

  it('getAddress() should derive from mnemonic', (done) => {
    // wallet with xpub
    const wallet = STORE.wallets[0]
    const address = keystore.getAddress(STORE.wallets, wallet.id)

    address.should.be.equal(STORE.firstDerivedAddress)

    done()
  })

  it('setAddressIndex() should set current address index', (done) => {
    // wallet with xpub
    const wallet = STORE.wallets[0]
    const { id } = wallet
    const addressIndex = 3
    const wallets = keystore.setAddressIndex(STORE.wallets, id, addressIndex)
    const walletWithChangedAddressIndex = wallets[0]

    walletWithChangedAddressIndex.should.be.an.Object()
    walletWithChangedAddressIndex.id.should.be.equal(id)
    walletWithChangedAddressIndex.addressIndex.should.be.equal(addressIndex)

    Object.assign(STORE, { wallets })

    done()
  })

  it('getMnemonic() should throw error (wallet is read only)', (done) => {
    try {
      // wallet with xpub
      const wallet = STORE.wallets[0]
      keystore.getMnemonic(STORE.wallets, wallet.id, password)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet is read only')

      done()
    }
  })

  it('setDerivationPath() should throw error (wallet is read only)', (done) => {
    try {
      // wallet with xpub
      const wallet = STORE.wallets[0]
      keystore.setDerivationPath(STORE.wallets, wallet.id, password)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet is read only')

      done()
    }
  })

  it('getPrivateKey() should throw error (for read only wallet)', (done) => {
    try {
      // wallet with xpub
      const wallet = STORE.wallets[0]
      keystore.getPrivateKey(STORE.wallets, wallet.id, password)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet is read only')

      done()
    }
  })

  it('getWalletData() should return wallet data', (done) => {
    // wallet with xpub
    const wallet = STORE.wallets[0]
    const walletData = keystore.getWalletData(STORE.wallets, wallet.id)

    walletData.should.be.an.Object()
    walletData.name.should.be.equal(name)
    walletData.id.should.be.equal(wallet.id)
    walletData.address.should.be.equal('n/a')
    walletData.readOnly.should.be.equal('yes')
    walletData.mnemonic.should.be.equal('n/a')
    walletData.privateKey.should.be.equal('n/a')
    walletData.type.should.be.equal('bip32Xpub')
    walletData.bip32XPublicKey.should.be.equal(bip32XPublicKey)

    done()
  })

  it('removeWallet() should throw error (incorrect walletId)', (done) => {
    try {
      keystore.removeWallet(STORE.wallets, incorrectWalletId)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal(`Wallet with id ${incorrectWalletId} not found`)

      done()
    }
  })

  it('removeWallet() should return changed list of wallets', (done) => {
    // wallet with xpub
    const wallet = STORE.wallets[0]
    const wallets = keystore.removeWallet(STORE.wallets, wallet.id)

    wallets.should.be.an.Array()
    wallets.length.should.be.equal(0)

    done()
  })
})

/* eslint-enable fp/no-mutating-assign */
