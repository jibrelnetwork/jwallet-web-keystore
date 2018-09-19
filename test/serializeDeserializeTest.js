/* eslint-disable fp/no-mutating-assign */

/* eslint-disable-next-line no-unused-vars */
import should from 'should'

import keystore from '../lib'
import packageData from '../package.json'

const name = 'mnemonic read only wallet'
const walletIdLength = 36
const currentKeystoreVersion = packageData.version

/* eslint-disable-next-line max-len */
const bip32XPublicKey = 'xpub6DZVENYSZsMW1D48vLG924qPaxz83TZc43tK7zMbCdFcv1La9pqe6pBiuxdzDNjufXRW42CfJEK8indRdhfDoWvYfZDZS1xjkZrQB5iYtHy'

const STORE = {
  wallets: [],
  serializedKeystoreData: null,
}

describe('serialize / deserialize', function serializeDeserializeTest() {
  this.timeout(20000)

  it('createWallet() should create example wallet', (done) => {
    const wallets = keystore.createWallet(STORE.wallets, {
      name,
      data: bip32XPublicKey,
    })

    wallets.should.be.an.Array()
    wallets.length.should.be.greaterThan(0)

    const wallet = wallets[0]

    wallet.should.be.an.Object()
    wallet.id.should.be.a.String()
    wallet.name.should.be.equal(name)
    wallet.id.length.should.be.equal(walletIdLength)
    wallet.bip32XPublicKey.should.be.equal(bip32XPublicKey)

    Object.assign(STORE, { wallets })

    done()
  })

  it('serialize() should serialize keystore data', (done) => {
    const serializedKeystoreData = keystore.serialize(STORE.wallets)

    serializedKeystoreData.should.be.a.String()
    serializedKeystoreData.length.should.be.greaterThan(0)

    Object.assign(STORE, { serializedKeystoreData })

    done()
  })

  it('deserialize() should restore and return deserialized keystore data', (done) => {
    const deserializedKeystoreData = keystore.deserialize(STORE.serializedKeystoreData)

    deserializedKeystoreData.wallets.should.be.an.Array()

    const { wallets } = deserializedKeystoreData

    wallets.should.be.an.Array()
    wallets.length.should.be.greaterThan(0)

    const wallet = wallets[0]

    wallet.should.be.an.Object()

    const walletFoundById = keystore.getWallet(wallets, wallet.id)

    walletFoundById.id.should.be.equal(wallet.id)

    deserializedKeystoreData.version.should.be.equal(currentKeystoreVersion)

    done()
  })

  it('deserialize() should throw error (parsing of data failed)', (done) => {
    try {
      keystore.deserialize('#')

      done(new Error('Exception not thrown'))
    } catch (e) {
      e.should.be.an.Object()
      e.message.should.be.equal('Failed to parse backup data')

      done()
    }
  })
})

/* eslint-enable fp/no-mutating-assign */
