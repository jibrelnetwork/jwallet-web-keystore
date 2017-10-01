const should = require('should')
const Keystore = require('../index')
const keystore = new Keystore()

const mnemonic = 'come average primary sunny profit eager toy pulp struggle hazard tourist round'

describe('isMnemonicValid', function() {
  it('should return true when generated Mnemonic is valid', function(done) {
    const isMnemonicValid = keystore.isMnemonicValid(mnemonic)

    isMnemonicValid.should.be.a.Boolean()
    isMnemonicValid.should.be.equal(true)

    done()
  })
})
