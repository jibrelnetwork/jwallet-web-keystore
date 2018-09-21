/* eslint-disable fp/no-mutating-assign */

/* eslint-disable-next-line no-unused-vars */
import should from 'should'

import keystore from '../lib'

const password = 'JHJ23jG^*DGHj667s'
const name = 'address read only wallet'
const walletIdLength = 36

const privateKeyAddressPair = {
  address: '0xb5c99109ded6212f667b9467a42dad1f195cdba9',
  privateKey: '0xa7fcb4efc392d2c8983cbfe64063f994f85120e60843407af95907d905d0dc9f',
}

/* eslint-disable max-len */
const mnemonicXPubPair = {
  mnemonic: 'sunny boil orient spawn edit voyage impose eager notice parent boat pudding',
  bip32XPublicKey: 'xpub6ENQhtq6UZ7CVznP3uC8mkb9FAfuMepKMdeaBiBoRZwUjZkoYgoXztnggqTfd7DkC8tTZsN5RSPh7Wme42PF8sSRSSCqqdg381zbu2QMEHc',
}
/* eslint-enable max-len */

const STORE = {
  wallets: [],
}

describe('extend wallet permissions', function extendPermissionsTest() {
  this.timeout(20000)

  describe('address read only wallet', () => {
    it('createReadOnlyAddressWallet() should return list with created wallet', (done) => {
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
      wallet.id.length.should.be.equal(walletIdLength)
      wallet.address.should.be.equal(privateKeyAddressPair.address)
      wallet.isReadOnly.should.be.equal(true)
      wallet.type.should.be.equal('address')
      wallet.customType.should.be.equal('address')

      wallet.encrypted.should.be.an.Object()
      should(wallet.encrypted.mnemonic).be.null()
      should(wallet.encrypted.privateKey).be.null()

      Object.assign(STORE, { wallets })

      done()
    })

    it('addPrivateKey() should return list with updated wallet', (done) => {
      // wallet with address
      const wallet = STORE.wallets[0]
      const { privateKey } = privateKeyAddressPair
      const wallets = keystore.addPrivateKey(STORE.wallets, wallet.id, privateKey, password)

      wallets.should.be.an.Array()

      const walletUpdated = wallets[0]

      walletUpdated.should.be.an.Object()
      walletUpdated.name.should.be.equal(name)
      walletUpdated.id.should.be.equal(wallet.id)
      walletUpdated.address.should.be.equal(privateKeyAddressPair.address)
      walletUpdated.isReadOnly.should.be.equal(false)
      walletUpdated.type.should.be.equal('address')
      walletUpdated.customType.should.be.equal('privateKey')

      should(wallet.encrypted.mnemonic).be.null()
      walletUpdated.encrypted.should.be.an.Object()
      walletUpdated.encrypted.privateKey.should.be.an.Object()
      walletUpdated.encrypted.privateKey.data.should.be.a.String()
      walletUpdated.encrypted.privateKey.nonce.should.be.a.String()

      // cleanup
      Object.assign(STORE, { wallets: [] })

      done()
    })
  })

  describe('mnemonic read only wallet', () => {
    it('createReadOnlyMnemonicWallet() should return list with created wallet', (done) => {
      const wallets = keystore.createWallet(STORE.wallets, {
        name,
        data: mnemonicXPubPair.bip32XPublicKey,
      })

      wallets.should.be.an.Array()
      wallets.length.should.be.greaterThan(0)

      const wallet = wallets[0]

      wallet.should.be.an.Object()
      wallet.id.should.be.a.String()
      wallet.name.should.be.equal(name)
      wallet.id.length.should.be.equal(walletIdLength)
      wallet.bip32XPublicKey.should.be.equal(mnemonicXPubPair.bip32XPublicKey)
      wallet.isReadOnly.should.be.equal(true)
      wallet.type.should.be.equal('mnemonic')
      wallet.customType.should.be.equal('bip32Xpub')

      wallet.encrypted.should.be.an.Object()
      should(wallet.encrypted.mnemonic).be.null()
      should(wallet.encrypted.privateKey).be.null()

      Object.assign(STORE, { wallets })

      done()
    })

    it('addMnemonic() should return list with updated wallet', (done) => {
      // wallet with address
      const wallet = STORE.wallets[0]
      const { mnemonic } = mnemonicXPubPair
      const wallets = keystore.addMnemonic(STORE.wallets, wallet.id, mnemonic, password)

      wallets.should.be.an.Array()

      const walletUpdated = wallets[0]

      walletUpdated.should.be.an.Object()
      walletUpdated.name.should.be.equal(name)
      walletUpdated.id.should.be.equal(wallet.id)
      walletUpdated.bip32XPublicKey.should.be.equal(mnemonicXPubPair.bip32XPublicKey)
      walletUpdated.isReadOnly.should.be.equal(false)
      walletUpdated.type.should.be.equal('mnemonic')
      walletUpdated.customType.should.be.equal('mnemonic')

      walletUpdated.encrypted.should.be.an.Object()
      should(wallet.encrypted.privateKey).be.null()
      walletUpdated.encrypted.mnemonic.should.be.an.Object()
      walletUpdated.encrypted.mnemonic.data.should.be.a.String()
      walletUpdated.encrypted.mnemonic.nonce.should.be.a.String()

      done()
    })
  })
})

/* eslint-enable fp/no-mutating-assign */
