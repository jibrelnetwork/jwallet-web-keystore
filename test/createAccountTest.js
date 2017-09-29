const should = require('should')
const AccountManager = require('../index')
const accountManager = new AccountManager()

describe('createAccount', function() {

  describe('create ReadOnly PrivateKey Account', function() {
    it('should create account and return id of it', function(done) {
      const accountData = {
        type: 'privateKey',
        isReadOnly: true,
        accountName: 'test account',
        password: 'K^JF%H87dadfH$#K8da',
        address: '8a02a99cc7a801da6996a2dacc406ffa5190dc9c',
      }

      const accountId = accountManager.createAccount(accountData)

      accountId.should.be.a.String()
      accountId.length.should.be.equal(36)

      done()
    })
  })

})
