const should = require('should')
const Keystore = require('../index')
const keystore = new Keystore()

const accountData = {
  type: 'address',
  isReadOnly: true,
  accountName: 'test account',
  password: 'K^JF%H87dadfH$#K8da',
  address: '8a02a99cc7a801da6996a2dacc406ffa5190dc9c',
}

const bip32XPublicKey = 'xpub6DZVENYSZsMW1D48vLG924qPaxz83TZc43tK7zMbCdFcv1La9pqe6pBiuxdzDNjufXRW42CfJEK8indRdhfDoWvYfZDZS1xjkZrQB5iYtHy'
const mnemonic = keystore.generateMnemonic().toString()

let addressAccountId
let mnemonicAccountId

describe('createAccount', function() {

  describe('create Account with wrong type', function() {
    it('should throw an error', function(done) {
      try {
        keystore.createAccount({
          ...accountData,
          type: 'some wrong type'
        })

        done(new Error('Error not thrown'))
      } catch (e) {
        done()
      }
    })

    it('should return empty accounts list', function(done) {
      const accounts = keystore.getAccounts()

      accounts.should.be.an.Array()
      accounts.length.should.be.equal(0)

      done()
    })
  })

  describe('create ReadOnly PrivateKey Account', function() {
    it('should create account and return id of it', function(done) {
      const accountId = keystore.createAccount(accountData)

      accountId.should.be.a.String()
      accountId.length.should.be.equal(36)

      done()
    })

    it('should return accounts list with one item', function(done) {
      const accounts = keystore.getAccounts()

      accounts.should.be.an.Array()
      accounts.length.should.be.equal(1)
      accounts[0].accountName.should.be.equal(accountData.accountName)

      done()
    })
  })

  describe('create FullAccess PrivateKey Account', function() {
    it('should create account and return id of it', function(done) {
      addressAccountId = keystore.createAccount({
        ...accountData,
        isReadOnly: false,
        privateKey: `0x${'1'.repeat(64)}`,
      })

      addressAccountId.should.be.a.String()
      addressAccountId.length.should.be.equal(36)

      done()
    })

    it('should return created account', function(done) {
      const account = keystore.getAccount({ id: addressAccountId })

      account.should.be.an.Object()
      account.id.should.be.equal(addressAccountId)

      done()
    })

    it('should return account privateKey', function(done) {
      const privateKey = keystore.getPrivateKey(accountData.password, addressAccountId)

      privateKey.should.be.a.String()
      privateKey.length.should.be.equal(66)

      done()
    })
  })

  describe('create ReadOnly Mnemonic Account', function() {
    it('should create account and return id of it', function(done) {
      mnemonicAccountId = keystore.createAccount({
        ...accountData,
        type: 'mnemonic',
        bip32XPublicKey,
      })

      mnemonicAccountId.should.be.a.String()
      mnemonicAccountId.length.should.be.equal(36)

      done()
    })

    it('should return privateKey derived from ReadOnly Mnemonic Account', function(done) {
      const privateKey = keystore.getPrivateKeyFromMnemonic(accountData.password, mnemonicAccountId)

      privateKey.should.be.a.String()
      privateKey.length.should.be.equal(64)

      done()
    })
  })

  describe('create FullAccess Mnemonic Account', function() {
    it('should create account and return id of it', function(done) {
      mnemonicAccountId = keystore.createAccount({
        ...accountData,
        type: 'mnemonic',
        isReadOnly: false,
        mnemonic,
      })

      mnemonicAccountId.should.be.a.String()
      mnemonicAccountId.length.should.be.equal(36)

      done()
    })

    it('should return privateKey derived from FullAccess Mnemonic Account', function(done) {
      const privateKey = keystore.getPrivateKeyFromMnemonic(accountData.password, mnemonicAccountId)

      privateKey.should.be.a.String()
      privateKey.length.should.be.equal(64)

      done()
    })
  })

})
