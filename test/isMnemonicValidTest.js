const should = require('should')
const AccountManager = require('../index')
const accountManager = new AccountManager()

describe('isMnemonicValid', function() {
  it('should return true when generated Mnemonic is valid', function(done) {
    const mnemonic = accountManager.generateMnemonic()
    const isMnemonicValid = AccountManager.isMnemonicValid(mnemonic)

    isMnemonicValid.should.be.a.Boolean()
    isMnemonicValid.should.be.equal(true)

    done()
  })
})
