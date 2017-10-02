const should = require('should')
const Keystore = require('../index')
const keystore = new Keystore()

const password = 'JHJ23jG^*DGHj667s'
const bip32XPublicKey = 'xpub6DZVENYSZsMW1D48vLG924qPaxz83TZc43tK7zMbCdFcv1La9pqe6pBiuxdzDNjufXRW42CfJEK8indRdhfDoWvYfZDZS1xjkZrQB5iYtHy'
const accountName = 'mnemonic read only account'
const accountIdLength = 36
const currentKeystoreVersion = 1

let accountId
let serializedKeystoreData

describe('serialize / deserialize', function() {
  this.timeout(20000)

  it('createAccount() should create example account', function(done) {
    accountId = keystore.createAccount({
      password,
      accountName,
      bip32XPublicKey,
      type: 'mnemonic',
      isReadOnly: true,
    })

    accountId.should.be.a.String()
    accountId.length.should.be.equal(accountIdLength)

    done()
  })

  it('serialize() should serialize keystore data', function(done) {
    serializedKeystoreData = keystore.serialize(password)

    serializedKeystoreData.should.be.a.String()
    serializedKeystoreData.length.should.be.greaterThan(0)

    done()
  })

  it('deserialize() should restore and return deserialized keystore data', function(done) {
    const deserializedKeystoreData = keystore.deserialize(serializedKeystoreData)

    deserializedKeystoreData.should.be.an.Object()
    deserializedKeystoreData.accounts.should.be.an.Array()
    deserializedKeystoreData.accounts[0].should.be.an.Object()
    deserializedKeystoreData.accounts[0].id.should.be.equal(accountId)
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
