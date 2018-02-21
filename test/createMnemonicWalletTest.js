const should = require('should')
const Keystore = require('../index')
const keystore = new Keystore()

const password = 'JHJ23jG^*DGHj667s'
const name = 'mnemonic wallet'
const derivationPath = "m/44'/60'/0'/0"
const customDerivationPath = "m/44'/60'/1'/0"
const customDerivationPath2 = "m/44'/60'/2'/0"
const mnemonicWordsCount = 12
const addressesCountToDerive = 5
const walletIdLength = 36
const addressLength = 42
const privateKeyLength = 66
const addressIndex = 3

const mnemonicXPubPair = {
  mnemonic: 'sunny boil orient spawn edit voyage impose eager notice parent boat pudding',
  bip32XPublicKey: 'xpub6ENQhtq6UZ7CVznP3uC8mkb9FAfuMepKMdeaBiBoRZwUjZkoYgoXztnggqTfd7DkC8tTZsN5RSPh7Wme42PF8sSRSSCqqdg381zbu2QMEHc',
  bip32XPublicKeyCustomPath: 'xpub6EHUjFfkAkfqXkqkcZKNxa4Gx6ybxSfRFFeUYsBsqm2Eg2xrz7KWtAmW1pdJ6DNA852xkLtCPTbCinawRFm29WD4XLF8npKNQNpYa42cCwy',
  bip32XPublicKeyCustomPath2: 'xpub6EzL2PV6NukMTntAULEUcdyNTzPvJDPFnog6p5fQek1ANmCm7sP1wJAFhFwBbxGESbzacQbivU97vGpuqzGrc3rVKSV8htoegG5TsrtNGUM',
}

let walletId
let firstDerivedAddress

describe('mnemonic wallet', function() {
  this.timeout(20000)

  it('createWallet() should create wallet and return id of it', function(done) {
    walletId = keystore.createWallet({
      name,
      password,
      type: 'mnemonic',
      isReadOnly: false,
      mnemonic: mnemonicXPubPair.mnemonic,
    })

    walletId.should.be.a.String()
    walletId.length.should.be.equal(walletIdLength)

    done()
  })

  it('createWallet() should throw error (mnemonic is invalid)', function(done) {
    try {
      keystore.createWallet({
        password,
        type: 'mnemonic',
        mnemonic: 'some wrong mnemonic',
      })

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Invalid mnemonic')

      done()
    }
  })

  it('createWallet() should throw error (wallet with this xpub exists)', function(done) {
    try {
      keystore.createWallet({
        password,
        type: 'mnemonic',
        mnemonic: mnemonicXPubPair.mnemonic,
      })

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet with this bip32XPublicKey already exists')

      done()
    }
  })

  it('createWallet() [READ ONLY] should throw error (wallet with this xpub exists)',
    function(done) {
      try {
        keystore.createWallet({
          password,
          type: 'mnemonic',
          isReadOnly: true,
          bip32XPublicKey: mnemonicXPubPair.bip32XPublicKey,
        })

        done(new Error('Exception not thrown'))
      } catch (e) {
        e.should.be.an.Object()
        e.message.should.be.equal('Wallet with this bip32XPublicKey already exists')

        done()
      }
    }
  )

  it('getWallets() should return wallets list with one item', function(done) {
    const wallets = keystore.getWallets()

    wallets.should.be.an.Array()
    wallets.length.should.be.equal(1)
    wallets[0].id.should.be.equal(walletId)
    wallets[0].name.should.be.equal(name)

    done()
  })

  it('getMnemonic() should get setted mnemonic', function(done) {
    const settedMnemonic = keystore.getMnemonic(password, walletId)
    const words = settedMnemonic.split(' ')

    settedMnemonic.should.be.a.String()
    settedMnemonic.length.should.be.greaterThan(0)
    words.length.should.be.equal(mnemonicWordsCount)
    settedMnemonic.should.be.equal(mnemonicXPubPair.mnemonic)

    done()
  })

  it('getAddressesFromMnemonic() should derive addresses from mnemonic with default path', function(done) {
    const addresses = keystore.getAddressesFromMnemonic(walletId)

    addresses.should.be.an.Array()
    addresses.length.should.be.equal(addressesCountToDerive)

    firstDerivedAddress = addresses[0]

    firstDerivedAddress.should.be.a.String()
    firstDerivedAddress.length.should.be.equal(addressLength)

    done()
  })

  it('setDerivationPath() should throw error (derivation path is invalid)', function(done) {
    try {
      keystore.setDerivationPath(password, walletId)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Invalid derivation path')

      done()
    }
  })

  it('setDerivationPath() should throw error (same derivation path)', function(done) {
    try {
      keystore.setDerivationPath(password, walletId, derivationPath)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Can not set the same derivation path')

      done()
    }
  })

  it('setDerivationPath() should throw error (wallet with this xpub exists)', function(done) {
    try {
      /**
       * This wallet will have the same bip32XPublicKey as the wallet,
       * that was created before with setted customDerivationPath
       * so exception will thrown
       */
      const newId = keystore.createWallet({
        password,
        type: 'mnemonic',
        isReadOnly: true,
        bip32XPublicKey: mnemonicXPubPair.bip32XPublicKeyCustomPath,
      })

      keystore.setDerivationPath(password, walletId, customDerivationPath)

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Wallet with this bip32XPublicKey already exists')

      done()
    }
  })

  it('setDerivationPath() should set custom derivation path', function(done) {
    const wallet = keystore.setDerivationPath(password, walletId, customDerivationPath2)

    wallet.should.be.an.Object()
    wallet.id.should.be.equal(walletId)
    wallet.derivationPath.should.be.equal(customDerivationPath2)

    done()
  })

  it('getAddressesFromMnemonic() should derive addresses from mnemonic with custom path', function(done) {
    const addresses = keystore.getAddressesFromMnemonic(walletId)

    addresses.should.be.an.Array()
    addresses.length.should.be.equal(addressesCountToDerive)

    const firstDerivedAddressWithCustomPath = addresses[0]

    firstDerivedAddressWithCustomPath.should.be.a.String()
    firstDerivedAddressWithCustomPath.length.should.be.equal(addressLength)
    firstDerivedAddressWithCustomPath.should.not.be.equal(firstDerivedAddress)

    done()
  })

  it('setAddressIndex() should set current address index', function(done) {
    const wallet = keystore.setAddressIndex(walletId, addressIndex)

    wallet.should.be.an.Object()
    wallet.id.should.be.equal(walletId)
    wallet.addressIndex.should.be.a.Number()
    wallet.addressIndex.should.be.equal(addressIndex)

    done()
  })

  it('getPrivateKey() should get private key (with current index)', function(done) {
    const privateKey = keystore.getPrivateKey(password, walletId)

    privateKey.should.be.a.String()
    privateKey.length.should.be.equal(privateKeyLength)

    done()
  })

  it('getDecryptedWallet() should get wallet data (with decrypted mnemonic)', function(done) {
    const decryptedWallet = keystore.getDecryptedWallet(password, walletId)

    decryptedWallet.should.be.an.Object()
    decryptedWallet.name.should.be.equal(name)
    decryptedWallet.id.should.be.equal(walletId)
    decryptedWallet.readOnly.should.be.equal('no')
    decryptedWallet.type.should.be.equal('mnemonic')
    decryptedWallet.mnemonic.should.be.equal(mnemonicXPubPair.mnemonic)
    decryptedWallet.bip32XPublicKey.should.be.equal(mnemonicXPubPair.bip32XPublicKeyCustomPath2)

    done()
  })
})
