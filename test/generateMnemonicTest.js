const should = require('should')
const AccountManager = require('../index')
const accountManager = new AccountManager()

describe('generateMnemonic', function() {
  it('should generate 24 random English words', function(done) {
    const mnemonic = accountManager.generateMnemonic()
    const words = mnemonic.split(' ')

    mnemonic.should.be.a.String()
    words.length.should.be.equal(24)

    done()
  })
})
