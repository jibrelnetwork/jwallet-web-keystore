/* eslint-disable fp/no-mutating-assign */

/* eslint-disable-next-line no-unused-vars */
import should from 'should'

import keystore from '../lib'

const password = 'JHJ23jG^*DGHj667s'
const passwordNew = 'Tw5E^g7djfd(29j'
const passwordWeak = 'some weak password'
const name = 'address wallet'
const walletNameUpdated = 'updated address wallet'
const walletIdLength = 36
const privateKeyLength = 66
const walletIdWrong = 'some_wrong_id'

const privateKeyAddressPair = {
  privateKey: '0xa7fcb4efc392d2c8983cbfe64063f994f85120e60843407af95907d905d0dc9f',
  address: '0xb5C99109DEd6212F667b9467a42DAD1F195cDBa9',
}

const STORE = {
  wallets: [],
}

describe('address wallet', function createAddressWalletTest() {
  this.timeout(20000)

  it('createWallet() should throw error (password is weak)', (done) => {
    try {
      keystore.createWallet(STORE.wallets, {
        name,
        data: privateKeyAddressPair.privateKey,
      }, passwordWeak)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('The password must contain at least one uppercase letter')

      done()
    }
  })

  it('createWallet() should create wallet and return id of it', (done) => {
    // wallet with privateKey
    const wallets = keystore.createWallet(STORE.wallets, {
      name,
      data: privateKeyAddressPair.privateKey,
    }, password)

    const wallet = wallets[0]

    wallet.should.be.an.Object()
    wallet.id.should.be.a.String()
    wallet.name.should.be.equal(name)
    wallet.id.length.should.be.equal(walletIdLength)

    wallet.encrypted.should.be.an.Object()
    should(wallet.encrypted.mnemonic).be.null()
    wallet.encrypted.privateKey.should.be.an.Object()
    wallet.encrypted.privateKey.data.should.be.a.String()
    wallet.encrypted.privateKey.data.length.should.be.greaterThan(0)

    Object.assign(STORE, { wallets })

    done()
  })

  it('createWallet() [READ ONLY] should throw error (wallet with this address exists)', (done) => {
    try {
      keystore.createWallet(STORE.wallets, {
        data: privateKeyAddressPair.address,
      }, password)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet with this address already exists')

      done()
    }
  })

  it('createWallet() should throw error (wallet data is invalid)', (done) => {
    try {
      keystore.createWallet(STORE.wallets, {
        data: 'qwert',
      }, password)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet data not provided or invalid')

      done()
    }
  })

  it('setWalletName() should throw error (empty new name)', (done) => {
    try {
      // wallet with privateKey
      const wallet = STORE.wallets[0]
      keystore.setWalletName(STORE.wallets, wallet.id, '')

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('New wallet name should not be empty')

      done()
    }
  })

  it('setWalletName() should throw error (for not existed wallet)', (done) => {
    try {
      keystore.setWalletName(STORE.wallets, walletIdWrong, '123')

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal(`Wallet with id ${walletIdWrong} not found`)

      done()
    }
  })

  it('setWalletName() should throw error (if name is the same)', (done) => {
    try {
      // wallet with privateKey
      const wallet = STORE.wallets[0]
      keystore.setWalletName(STORE.wallets, wallet.id, name)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('New wallet name should not be equal with the old one')

      done()
    }
  })

  it('setWalletName() should throw error (wallet with this name exists)', (done) => {
    // wallet with generated privateKey
    const wallets = keystore.createWallet(STORE.wallets, {
      data: `0x${'1'.repeat(64)}`,
    }, password)

    Object.assign(STORE, { wallets })

    try {
      const wallet = STORE.wallets[1]
      keystore.setWalletName(STORE.wallets, wallet.id, name)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet with this name already exists')

      done()
    }
  })

  it('setWalletName() should update wallet name', (done) => {
    // wallet with privateKey
    const wallet = STORE.wallets[0]
    const wallets = keystore.setWalletName(STORE.wallets, wallet.id, walletNameUpdated)
    const walletWithChangedName = keystore.getWallet(wallets, wallet.id)

    walletWithChangedName.should.be.an.Object()
    walletWithChangedName.id.should.be.equal(wallet.id)
    walletWithChangedName.name.should.be.equal(walletNameUpdated)

    Object.assign(STORE, { wallets })

    done()
  })

  it('getWallet() should return updated wallet', (done) => {
    // wallet with privateKey
    const wallet = STORE.wallets[1]
    const walletFoundById = keystore.getWallet(STORE.wallets, wallet.id)

    walletFoundById.id.should.be.equal(wallet.id)
    walletFoundById.name.should.be.equal(walletNameUpdated)

    done()
  })

  it('getAddress() should get wallet address', (done) => {
    // wallet with privateKey
    const wallet = STORE.wallets[1]
    const walletAddress = keystore.getAddress(STORE.wallets, wallet.id)

    walletAddress.should.be.equal(privateKeyAddressPair.address)

    done()
  })

  it('setPassword() should change wallet password', (done) => {
    // wallet with privateKey
    const wallet = STORE.wallets[1]
    const wallets = keystore.setPassword(STORE.wallets, wallet.id, password, passwordNew)

    Object.assign(STORE, { wallets })

    done()
  })

  it('getPrivateKey() should get wallet private key', (done) => {
    // wallet with privateKey
    const wallet = STORE.wallets[1]
    const walletId = wallet.id
    const privateKey = keystore.getPrivateKey(STORE.wallets, walletId, passwordNew)

    privateKey.should.be.a.String()
    privateKey.length.should.be.equal(privateKeyLength)
    privateKey.should.be.equal(privateKeyAddressPair.privateKey)

    done()
  })

  it('getMnemonic() should throw error (wrong type)', (done) => {
    try {
      // wallet with privateKey
      const wallet = STORE.wallets[1]
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
      // wallet with privateKey
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
      // wallet with privateKey
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
      // wallet with privateKey
      const wallet = STORE.wallets[1]
      keystore.setDerivationPath(STORE.wallets, wallet.id, password)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet type is not mnemonic')

      done()
    }
  })

  it('getWalletData() should return wallet data (with decrypted private key)', (done) => {
    // wallet with privateKey
    const wallet = STORE.wallets[1]
    const walletData = keystore.getWalletData(STORE.wallets, wallet.id, passwordNew)

    walletData.should.be.an.Object()
    walletData.id.should.be.equal(wallet.id)
    walletData.readOnly.should.be.equal('no')
    walletData.mnemonic.should.be.equal('n/a')
    walletData.type.should.be.equal('privateKey')
    walletData.bip32XPublicKey.should.be.equal('n/a')
    walletData.name.should.be.equal(walletNameUpdated)
    walletData.address.should.be.equal(privateKeyAddressPair.address)
    walletData.privateKey.should.be.equal(privateKeyAddressPair.privateKey)

    done()
  })

  it('removeWallet() should return changed list of wallets', (done) => {
    // wallet with address
    const walletWithAddress = STORE.wallets[0]
    const walletsFirst = keystore.removeWallet(STORE.wallets, walletWithAddress.id)

    walletsFirst.should.be.an.Array()
    walletsFirst.length.should.be.equal(1)

    // wallet with privateKey
    const walletWithPrivateKey = walletsFirst[0]
    const walletsSecond = keystore.removeWallet(walletsFirst, walletWithPrivateKey.id)

    walletsSecond.should.be.an.Array()
    walletsSecond.length.should.be.equal(0)

    Object.assign(STORE, { wallets: walletsSecond })

    done()
  })
})

/* eslint-enable fp/no-mutating-assign */
