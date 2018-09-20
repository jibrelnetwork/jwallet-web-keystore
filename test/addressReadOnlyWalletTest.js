/* eslint-disable fp/no-mutating-assign */

/* eslint-disable-next-line no-unused-vars */
import should from 'should'

import keystore from '../lib'

const password = 'JHJ23jG^*DGHj667s'
const name = 'address read only wallet'
const walletIdLength = 36
const walletNameUpdated = 'updated address wallet'

const privateKeyAddressPair = {
  privateKey: '0xa7fcb4efc392d2c8983cbfe64063f994f85120e60843407af95907d905d0dc9f',
  address: '0xb5c99109ded6212f667b9467a42dad1f195cdba9',
}

const STORE = {
  wallets: [],
}

describe('address read only wallet', function createReadOnlyAddressWalletTest() {
  this.timeout(20000)

  it('createWallet() should create wallet and return updated list with it', (done) => {
    const wallets = keystore.createWallet(STORE.wallets, {
      name,
      data: privateKeyAddressPair.address,
    })

    wallets.should.be.an.Array()
    wallets.length.should.be.greaterThan(0)

    const wallet = wallets[0]

    wallet.should.be.an.Object()
    wallet.id.should.be.a.String()
    wallet.name.should.be.equal(name)
    should(wallet.addressIndex).be.null()
    wallet.type.should.be.equal('address')
    wallet.isReadOnly.should.be.equal(true)
    should(wallet.bip32XPublicKey).be.null()
    wallet.customType.should.be.equal('address')
    wallet.id.length.should.be.equal(walletIdLength)
    wallet.address.should.be.equal(privateKeyAddressPair.address)

    wallet.encrypted.should.be.an.Object()
    should(wallet.encrypted.mnemonic).be.null()
    should(wallet.encrypted.privateKey).be.null()

    should(wallet.passwordOptions).be.null()
    should(wallet.mnemonicOptions).be.null()

    Object.assign(STORE, { wallets })

    done()
  })

  it('createWallet() [FULL ACCESS] should throw error (wallet with the address exists)', (done) => {
    try {
      keystore.createWallet(STORE.wallets, {
        data: privateKeyAddressPair.privateKey,
      }, password)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet with this address already exists')

      done()
    }
  })

  it('createWallet() should throw error (wallet with this name exists)', (done) => {
    try {
      keystore.createWallet(STORE.wallets, {
        name,
        data: privateKeyAddressPair.address,
      })

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet with this name already exists')

      done()
    }
  })

  it('getAddress() should get wallet address', (done) => {
    // wallet with address
    const wallet = STORE.wallets[0]
    const walletAddress = keystore.getAddress(STORE.wallets, wallet.id)

    walletAddress.should.be.equal(privateKeyAddressPair.address)

    done()
  })

  it('setWalletName() should update wallet name', (done) => {
    // wallet with address
    const wallet = STORE.wallets[0]
    const wallets = keystore.setWalletName(STORE.wallets, wallet.id, walletNameUpdated)
    const walletWithChangedName = keystore.getWallet(wallets, wallet.id)

    walletWithChangedName.should.be.an.Object()
    walletWithChangedName.id.should.be.equal(wallet.id)
    walletWithChangedName.name.should.be.equal(walletNameUpdated)

    // do not rewrite STORE.wallets to left old name, it will be checked later

    done()
  })

  it('getMnemonic() should throw error (wrong type)', (done) => {
    try {
      // wallet with address
      const wallet = STORE.wallets[0]
      keystore.getMnemonic(STORE.wallets, wallet.id, password)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet type is not mnemonic')

      done()
    }
  })

  it('getAddresses() should throw error (wrong type)', (done) => {
    try {
      // wallet with address
      const wallet = STORE.wallets[0]
      keystore.getAddresses(STORE.wallets, wallet.id)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet type is not mnemonic')

      done()
    }
  })

  it('setAddressIndex() should throw error (wrong type)', (done) => {
    try {
      // wallet with address
      const wallet = STORE.wallets[0]
      keystore.setAddressIndex(STORE.wallets, wallet.id)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet type is not mnemonic')

      done()
    }
  })

  it('setDerivationPath() should throw error (wallet type is not mnemonic)', (done) => {
    try {
      // wallet with address
      const wallet = STORE.wallets[0]
      keystore.setDerivationPath(STORE.wallets, wallet.id, password)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet type is not mnemonic')

      done()
    }
  })

  it('getWallet() should return created wallet', (done) => {
    // wallet with address
    const walletCreated = STORE.wallets[0]
    const wallet = keystore.getWallet(STORE.wallets, walletCreated.id)

    wallet.should.be.an.Object()
    wallet.name.should.be.equal(name)
    wallet.id.should.be.equal(walletCreated.id)
    wallet.address.should.be.equal(privateKeyAddressPair.address)

    done()
  })

  it('getWallet() should throw error (without wallet id)', (done) => {
    try {
      keystore.getWallet(STORE.wallets)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet ID not provided')

      done()
    }
  })

  it('getPrivateKey() should throw error (for read only wallet)', (done) => {
    try {
      // wallet with address
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
    // wallet with address
    const wallet = STORE.wallets[0]
    const walletData = keystore.getWalletData(STORE.wallets, wallet.id)

    walletData.should.be.an.Object()
    walletData.name.should.be.equal(name)
    walletData.id.should.be.equal(wallet.id)
    walletData.readOnly.should.be.equal('yes')
    walletData.type.should.be.equal('address')
    walletData.mnemonic.should.be.equal('n/a')
    walletData.privateKey.should.be.equal('n/a')
    walletData.bip32XPublicKey.should.be.equal('n/a')
    walletData.address.should.be.equal(privateKeyAddressPair.address)

    done()
  })

  it('removeWallet() should return changed list of wallets', (done) => {
    // wallet with address
    const wallet = STORE.wallets[0]
    const wallets = keystore.removeWallet(STORE.wallets, wallet.id)

    wallets.should.be.an.Array()
    wallets.length.should.be.equal(0)

    done()
  })
})

/* eslint-enable fp/no-mutating-assign */
