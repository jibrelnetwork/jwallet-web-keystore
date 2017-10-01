const should = require('should')
const Keystore = require('../index')
const keystore = new Keystore()

describe('generateMnemonic', function() {
  it('should generate 12 random English words', function(done) {
    const mnemonic = keystore.generateMnemonic()
    const words = mnemonic.toString().split(' ')

    mnemonic.should.be.an.Object()
    words.length.should.be.equal(12)

    done()
  })
})
