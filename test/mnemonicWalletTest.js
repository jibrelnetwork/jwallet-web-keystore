/* eslint-disable fp/no-mutating-assign */

/* eslint-disable-next-line no-unused-vars */
import should from 'should'

import keystore from '../lib'

const password = 'JHJ23jG^*DGHj667s'
const passwordInvalid = 'nuts'
const name = 'mnemonic wallet'
const walletIdWrong = '123'
const derivationPath = 'm/44\'/60\'/0\'/0'
const derivationPathCustomA = 'm/44\'/60\'/1\'/0'
const derivationPathCustomB = 'm/44\'/60\'/2\'/0'
const passphrase = 'testmnemonicpassphrase'
const mnemonicWordsCount = 12
const addressesCountToDerive = 5
const walletIdLength = 36
const addressLength = 42
const privateKeyLength = 66
const addressIndex = 3
const addressStartIndex = 0
const addressEndIndex = 4
const walletNameUpdated = 'updated address wallet'

/* eslint-disable max-len */
const mnemonicXPubPair = {
  mnemonic: 'sunny boil orient spawn edit voyage impose eager notice parent boat pudding',
  bip32XPublicKey: 'xpub6ENQhtq6UZ7CVznP3uC8mkb9FAfuMepKMdeaBiBoRZwUjZkoYgoXztnggqTfd7DkC8tTZsN5RSPh7Wme42PF8sSRSSCqqdg381zbu2QMEHc',
  bip32XPublicKeyCustomPathA: 'xpub6EHUjFfkAkfqXkqkcZKNxa4Gx6ybxSfRFFeUYsBsqm2Eg2xrz7KWtAmW1pdJ6DNA852xkLtCPTbCinawRFm29WD4XLF8npKNQNpYa42cCwy',
  bip32XPublicKeyCustomPathB: 'xpub6EzL2PV6NukMTntAULEUcdyNTzPvJDPFnog6p5fQek1ANmCm7sP1wJAFhFwBbxGESbzacQbivU97vGpuqzGrc3rVKSV8htoegG5TsrtNGUM',
  bip32XPublicKeyPassphrase: 'xpub6EydSBqvYKr4nyKxnZi2mWgyGDj9wLRXSzhCqJXgFycBRWdHamjPCwLVqEaXvpZ7bVfUegBqfMY3pKh5vUJ4hpyLvMYBP2DsmFDqk4oKrMw',
}
/* eslint-enable max-len */

const STORE = {
  wallets: [],
  firstDerivedAddress: null,
}

describe('mnemonic wallet', function createMnemonicWalletTest() {
  this.timeout(20000)

  it('createWallet() should create wallet and return id of it', (done) => {
    const wallets = keystore.createWallet(STORE.wallets, {
      name,
      data: mnemonicXPubPair.mnemonic,
    }, password)

    wallets.should.be.an.Array()
    wallets.length.should.be.greaterThan(0)

    // wallet with mnemonic
    const wallet = wallets[0]

    wallet.should.be.an.Object()
    wallet.id.should.be.a.String()
    should(wallet.address).be.null()
    wallet.name.should.be.equal(name)
    wallet.addressIndex.should.be.equal(0)
    wallet.type.should.be.equal('mnemonic')
    wallet.isReadOnly.should.be.equal(false)
    wallet.customType.should.be.equal('mnemonic')
    wallet.id.length.should.be.equal(walletIdLength)
    wallet.bip32XPublicKey.should.be.equal(mnemonicXPubPair.bip32XPublicKey)

    wallet.encrypted.should.be.an.Object()
    should(wallet.encrypted.privateKey).be.null()
    wallet.encrypted.mnemonic.should.be.an.Object()
    wallet.encrypted.mnemonic.data.should.be.a.String()
    wallet.encrypted.mnemonic.data.length.should.be.greaterThan(0)

    wallet.mnemonicOptions.should.be.an.Object()
    wallet.passwordOptions.should.be.an.Object()
    wallet.passwordOptions.scryptParams.should.be.an.Object()
    wallet.mnemonicOptions.derivationPath.should.be.a.String()

    Object.assign(STORE, { wallets })

    done()
  })

  it('createWallet() should throw error (wallet data not provided)', (done) => {
    try {
      keystore.createWallet(STORE.wallets, {}, password)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet data not provided or invalid')

      done()
    }
  })

  it('createWallet() should throw error (wallet data is invalid)', (done) => {
    try {
      keystore.createWallet(STORE.wallets, {
        data: 'some wrong mnemonic',
      }, password)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet data not provided or invalid')

      done()
    }
  })

  it('createWallet() should throw error (wallet with this xpub exists)', (done) => {
    try {
      keystore.createWallet(STORE.wallets, {
        data: mnemonicXPubPair.mnemonic,
      }, password)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet with this bip32XPublicKey already exists')

      done()
    }
  })

  it('createWallet() [READ ONLY] should throw error (wallet with this xpub exists)', (done) => {
    try {
      keystore.createWallet(STORE.wallets, {
        data: mnemonicXPubPair.bip32XPublicKey,
      }, password)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet with this bip32XPublicKey already exists')

      done()
    }
  })

  it('setWalletName() should update wallet name', (done) => {
    // wallet with mnemonic
    const wallet = STORE.wallets[0]
    const wallets = keystore.setWalletName(STORE.wallets, wallet.id, walletNameUpdated)
    const walletWithChangedName = keystore.getWallet(wallets, wallet.id)

    walletWithChangedName.should.be.an.Object()
    walletWithChangedName.id.should.be.equal(wallet.id)
    walletWithChangedName.name.should.be.equal(walletNameUpdated)

    // do not rewrite STORE.wallets to left old name, it will be checked later

    done()
  })

  it('getMnemonic() should get setted mnemonic', (done) => {
    // wallet with mnemonic
    const wallet = STORE.wallets[0]
    const mnemonic = keystore.getMnemonic(STORE.wallets, wallet.id, password)
    const words = mnemonic.split(' ')

    words.should.be.an.Array()
    words.length.should.be.equal(mnemonicWordsCount)
    mnemonic.should.be.equal(mnemonicXPubPair.mnemonic)

    done()
  })

  it('getMnemonic() should throw error (password is empty)', (done) => {
    try {
      // wallet with mnemonic
      const wallet = STORE.wallets[0]
      keystore.getMnemonic(STORE.wallets, wallet.id)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Password is empty')

      done()
    }
  })

  it('getMnemonic() should throw error (password is invalid)', (done) => {
    try {
      // wallet with mnemonic
      const wallet = STORE.wallets[0]
      keystore.getMnemonic(STORE.wallets, wallet.id, passwordInvalid)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Password is invalid')

      done()
    }
  })

  it('getMnemonic() should throw error (wallet not found)', (done) => {
    try {
      keystore.getMnemonic(STORE.wallets, walletIdWrong)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal(`Wallet with id ${walletIdWrong} not found`)

      done()
    }
  })

  it('getAddresses() should derive addresses from mnemonic with default path', (done) => {
    // wallet with mnemonic
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

  it('getAddresses() should derive just one address (with no indexes in params)', (done) => {
    // wallet with mnemonic
    const wallet = STORE.wallets[0]
    const addresses = keystore.getAddresses(STORE.wallets, wallet.id)

    addresses.should.be.an.Array()
    addresses.length.should.be.equal(1)
    addresses[0].should.be.equal(STORE.firstDerivedAddress)

    done()
  })

  it('getAddress() should derive from mnemonic', (done) => {
    // wallet with xpub
    const wallet = STORE.wallets[0]
    const address = keystore.getAddress(STORE.wallets, wallet.id)

    address.should.be.equal(STORE.firstDerivedAddress)

    done()
  })

  it('setDerivationPath() should throw error (derivation path is invalid)', (done) => {
    try {
      // wallet with mnemonic
      const wallet = STORE.wallets[0]
      keystore.setDerivationPath(STORE.wallets, wallet.id, password)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Invalid derivation path')

      done()
    }
  })

  it('setDerivationPath() should throw error (same derivation path)', (done) => {
    try {
      // wallet with mnemonic
      const wallet = STORE.wallets[0]
      keystore.setDerivationPath(STORE.wallets, wallet.id, password, derivationPath)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Can not set the same derivation path')

      done()
    }
  })

  it('setDerivationPath() should throw error (wallet with this xpub exists)', (done) => {
    try {
      /**
       * This wallet will have the same bip32XPublicKey as the wallet,
       * that was created before with setted derivationPathCustomA
       * so exception will thrown
       */
      const wallets = keystore.createWallet(STORE.wallets, {
        data: mnemonicXPubPair.bip32XPublicKeyCustomPathA,
      }, password)

      Object.assign(STORE, { wallets })

      // wallet with mnemonic
      const wallet = STORE.wallets[0]
      keystore.setDerivationPath(STORE.wallets, wallet.id, password, derivationPathCustomA)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet with this bip32XPublicKey already exists')

      done()
    }
  })

  it('setDerivationPath() should set custom derivation path', (done) => {
    // wallet with mnemonic
    const wallet = STORE.wallets[0]
    const { id } = wallet
    const wallets = keystore.setDerivationPath(STORE.wallets, id, password, derivationPathCustomB)
    const walletWithChangedPath = keystore.getWallet(wallets, id)

    walletWithChangedPath.should.be.an.Object()
    walletWithChangedPath.id.should.be.equal(id)
    walletWithChangedPath.mnemonicOptions.should.be.an.Object()
    walletWithChangedPath.mnemonicOptions.derivationPath.should.be.equal(derivationPathCustomB)

    Object.assign(STORE, { wallets })

    done()
  })

  it('setMnemonicPassphrase() should set new mnemonic passphrase', (done) => {
    // wallet with mnemonic
    const wallet = STORE.wallets[1]
    const { id } = wallet
    const wallets = keystore.setMnemonicPassphrase(STORE.wallets, id, password, passphrase)
    const walletWithPassphrase = keystore.getWallet(wallets, id)

    walletWithPassphrase.should.be.an.Object()
    walletWithPassphrase.id.should.be.equal(id)
    walletWithPassphrase.mnemonicOptions.should.be.an.Object()
    walletWithPassphrase.mnemonicOptions.passphrase.should.be.equal(passphrase)
    walletWithPassphrase.bip32XPublicKey.should.be.equal(mnemonicXPubPair.bip32XPublicKeyPassphrase)

    Object.assign(STORE, { wallets })

    done()
  })

  it('getAddresses() should derive addresses from mnemonic with custom path', (done) => {
    // wallet with mnemonic
    const wallet = STORE.wallets[1]
    const { id } = wallet
    const addresses = keystore.getAddresses(STORE.wallets, id, addressStartIndex, addressEndIndex)

    addresses.should.be.an.Array()
    addresses.length.should.be.equal(addressesCountToDerive)

    const firstDerivedAddressWithCustomPath = addresses[0]

    firstDerivedAddressWithCustomPath.should.be.a.String()
    firstDerivedAddressWithCustomPath.length.should.be.equal(addressLength)
    firstDerivedAddressWithCustomPath.should.not.be.equal(STORE.firstDerivedAddress)

    done()
  })

  it('setAddressIndex() should set current address index', (done) => {
    // wallet with mnemonic
    const wallet = STORE.wallets[1]
    const wallets = keystore.setAddressIndex(STORE.wallets, wallet.id, addressIndex)
    const walletWithChangedAddressIndex = keystore.getWallet(wallets, wallet.id)

    walletWithChangedAddressIndex.should.be.an.Object()
    walletWithChangedAddressIndex.id.should.be.equal(wallet.id)
    walletWithChangedAddressIndex.addressIndex.should.be.equal(addressIndex)

    Object.assign(STORE, { wallets })

    done()
  })

  it('getPrivateKey() should get private key (with current index)', (done) => {
    // wallet with mnemonic
    const wallet = STORE.wallets[1]
    const privateKey = keystore.getPrivateKey(STORE.wallets, wallet.id, password)

    privateKey.length.should.be.equal(privateKeyLength)

    done()
  })

  it('getWalletData() should get wallet data (with decrypted mnemonic)', (done) => {
    // wallet with mnemonic
    const wallet = STORE.wallets[1]
    const walletData = keystore.getWalletData(STORE.wallets, wallet.id, password)

    walletData.should.be.an.Object()
    walletData.name.should.be.equal(name)
    walletData.id.should.be.equal(wallet.id)
    walletData.address.should.be.equal('n/a')
    walletData.readOnly.should.be.equal('no')
    walletData.type.should.be.equal('mnemonic')
    walletData.privateKey.should.be.equal('n/a')
    walletData.mnemonic.should.be.equal(mnemonicXPubPair.mnemonic)
    walletData.bip32XPublicKey.should.be.equal(mnemonicXPubPair.bip32XPublicKeyPassphrase)

    done()
  })

  it('removeWallet() should return changed list of wallets', (done) => {
    // wallet with xpub
    const walletWithXpub = STORE.wallets[0]
    const walletsFirst = keystore.removeWallet(STORE.wallets, walletWithXpub.id)

    walletsFirst.should.be.an.Array()
    walletsFirst.length.should.be.equal(1)

    // wallet with mnemonic
    const walletWithMnemonic = walletsFirst[0]
    const walletsSecond = keystore.removeWallet(walletsFirst, walletWithMnemonic.id)

    walletsSecond.should.be.an.Array()
    walletsSecond.length.should.be.equal(0)

    Object.assign(STORE, { wallets: walletsSecond })

    done()
  })
})

/* eslint-enable fp/no-mutating-assign */
