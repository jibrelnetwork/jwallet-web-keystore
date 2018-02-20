const should = require('should')

const packageData = require('../package.json')

const Keystore = require('../index')
const keystore = new Keystore()

const password = 'JHJ23jG^*DGHj667s'
const bip32XPublicKey = 'xpub6DZVENYSZsMW1D48vLG924qPaxz83TZc43tK7zMbCdFcv1La9pqe6pBiuxdzDNjufXRW42CfJEK8indRdhfDoWvYfZDZS1xjkZrQB5iYtHy'
const name = 'mnemonic read only wallet'
const walletIdLength = 36
const currentKeystoreVersion = packageData.version

let walletId
let serializedKeystoreData

describe('serialize / deserialize', function() {
  this.timeout(20000)

  it('createWallet() should create example wallet', function(done) {
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

  it('serialize() should serialize keystore data', function(done) {
    serializedKeystoreData = keystore.serialize()

    serializedKeystoreData.should.be.a.String()
    serializedKeystoreData.length.should.be.greaterThan(0)

    done()
  })

  it('deserialize() should restore and return deserialized keystore data', function(done) {
    const deserializedKeystoreData = keystore.deserialize(serializedKeystoreData)

    deserializedKeystoreData.should.be.an.Object()
    deserializedKeystoreData.wallets.should.be.an.Array()
    deserializedKeystoreData.wallets[0].should.be.an.Object()
    deserializedKeystoreData.wallets[0].id.should.be.equal(walletId)
    deserializedKeystoreData.version.should.be.equal(currentKeystoreVersion)

    done()
  })

  it('deserialize() should throw error (parsing of data failed)', function(done) {
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
