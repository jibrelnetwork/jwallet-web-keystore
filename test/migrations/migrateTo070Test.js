const should = require('should')
const Keystore = require('../../index')
const keystore = new Keystore()

const mnemonic1 = 'vehicle judge dumb quit traffic casino diet tumble cushion crawl staff powder'
const bip32XPublicKey1 = 'xpub6EVuRRjqi8cJGhnrCBt1SeichvkwUpUxe3Ba6xDdj4fueJNrPrV3fMJcMqnBBTioiNRVSCE8N6UbKB44BUXNJPJcvVxVq2G99Tj3ozJruyb'
const privateKey1 = '0x66013b232ab426b1382025d58c92a9ca9c79d846f42df70c2acea32229d74d7d'
const address1 = '0x21668533136022be631cc45d61D72B09A19A15Be'

const mnemonic2 = 'fault hair edit yellow loyal fashion link meat now scout rubber tobacco'
const bip32XPublicKey2 = 'xpub6ETrXfzjrzot6VwzoKCLBrcNJXx8YKcqfzdw8RgymXoAuhrsVxpBXuD5Bnd48S91MdwgKZZKAndoDCrBb6KPGBTbbPuJAcZ9XTuupqmcMiS'
const privateKey2 = '0x1b30dca29ec418a3729dcb6ae1df932e5f3a40ff6ce3ce5bc63f9ce406b4c96b'
const address2 = '0x1B2e1B25904C1cD231932E641A61107F9B87d8ca'

const password = 'qwert12345!Q'

const keystoreMock = {
  "accounts": [
    {"type":"mnemonic","id":"fb5f4f23-d73d-43af-bb6c-22e47519c1a4","accountName":"mnemonic1","derivationPath":"m/44'/60'/0'/0","bip32XPublicKey":"xpub6EVuRRjqi8cJGhnrCBt1SeichvkwUpUxe3Ba6xDdj4fueJNrPrV3fMJcMqnBBTioiNRVSCE8N6UbKB44BUXNJPJcvVxVq2G99Tj3ozJruyb","isReadOnly":false,"addressIndex":0,"encrypted":{"mnemonic":{"encryptionType":"nacl.secretbox","nonce":"S0lYcrvNVGtGkilF6grHrQyf1tYi7wSM","encryptedData":"k0coOe6LOZBD6Wn4B7MSIjAbE0lxnqMAIcQi+OcwNcThnFNLjBhFzvNGa+bP+qfZunBb1cOF49ej8ZQG0vVD8Rhg7F+gMRy4nw1xTcJDCyEGAumutnAFy1nBf2AD1ulgp9epfZkSzj0H749l+9oLLB8gChx01eAumKhqP1gL2qQUt4arkRW7GA=="}}},
    {"type":"address","id":"d840ac8f-7d51-4e7f-9dc8-165bddb92d38","address":"0x21668533136022be631cc45d61d72b09a19a15be","addressLowerCase":"0x21668533136022be631cc45d61d72b09a19a15be","accountName":"privateKey1","isReadOnly":false,"encrypted":{"privateKey":{"encryptionType":"nacl.secretbox","nonce":"HgL9jF1nbKcpI5B/bmjSk+DXlsYzLTPn","encryptedData":"qn9BHi4Zjk4/QCg8Cg/9SllIR/rDCCdirOZiAYpcSb/ieTH9sUI393+I7an1LL9vUBWgdH21/2ntwKCsE8II9w1c7gCrtnAV6ckNyyWSSR8hsw=="}}},
    {"type":"mnemonic","id":"414b2ddd-a19d-4a97-994d-2d7bb12ee23a","accountName":"bip32XPublicKey2","bip32XPublicKey":"xpub6ETrXfzjrzot6VwzoKCLBrcNJXx8YKcqfzdw8RgymXoAuhrsVxpBXuD5Bnd48S91MdwgKZZKAndoDCrBb6KPGBTbbPuJAcZ9XTuupqmcMiS","isReadOnly":true,"addressIndex":0,"encrypted":{}},
    {"type":"address","id":"11fe0f2f-068a-4bf9-852d-713373697a5c","address":"0x1b2e1b25904c1cd231932e641a61107f9b87d8ca","addressLowerCase":"0x1b2e1b25904c1cd231932e641a61107f9b87d8ca","accountName":"address2","isReadOnly":true,"encrypted":{}},
  ],
  "defaultDerivationPath": "m/44'/60'/0'/0",
  "defaultEncryptionType": "nacl.secretbox",
  "scryptParams": {"N":8,"r":8,"p":1},
  "derivedKeyLength": 32,
  "checkPasswordData": {"encryptionType":"nacl.secretbox","nonce":"NKDcLf0hxw4CTV58MKf0V3PQp5l/VkNQ","encryptedData":"iMpb/8ZbKL1mQB6OBlC0W5WRdDGbwcwbvEAv7fFH8fa/qhT3t3kPHQw7p1F3T+Cpvms3zO3gODZWuMS5"},
  "salt": "T4sbnly7qGFhhkc65llbAJfgnlrMnShu81RIRgu3c4s=",
  "version": "0.6.0",
}

const mnemonicWalletId = keystoreMock.accounts[0].id
const privateKeyWalletId = keystoreMock.accounts[1].id
const bip32XPublicKeyWalletId = keystoreMock.accounts[2].id
const addressWalletId = keystoreMock.accounts[3].id

const serializedKeystore = JSON.stringify(keystoreMock)

describe('migrate to 0.7.0', function() {
  this.timeout(20000)

  it('migrate() should prepare backup data to appropriate format', function(done) {
    keystore.deserialize(serializedKeystore)

    keystore.getWallets().length.should.be.equal(keystoreMock.accounts.length)

    const decryptedMnemonicWallet = keystore.getDecryptedWallet(password, mnemonicWalletId)
    const decryptedPrivateKeyWallet = keystore.getDecryptedWallet(password, privateKeyWalletId)
    const bip32XPublicKeyWallet = keystore.getWallet(bip32XPublicKeyWalletId)
    const addressWallet = keystore.getWallet(addressWalletId)

    decryptedMnemonicWallet.readOnly.should.be.equal('no')
    decryptedMnemonicWallet.type.should.be.equal('mnemonic')
    decryptedMnemonicWallet.mnemonic.should.be.equal(mnemonic1)
    decryptedMnemonicWallet.id.should.be.equal(mnemonicWalletId)
    decryptedMnemonicWallet.name.should.be.equal(keystoreMock.accounts[0].accountName)
    decryptedMnemonicWallet.bip32XPublicKey.should.be.equal(keystoreMock.accounts[0].bip32XPublicKey)
    keystore.getAddress(mnemonicWalletId).should.be.equal(address1)

    decryptedPrivateKeyWallet.readOnly.should.be.equal('no')
    decryptedPrivateKeyWallet.type.should.be.equal('privateKey')
    decryptedPrivateKeyWallet.id.should.be.equal(privateKeyWalletId)
    decryptedPrivateKeyWallet.privateKey.should.be.equal(privateKey1)
    decryptedPrivateKeyWallet.address.should.be.equal(address1.toLowerCase())
    decryptedPrivateKeyWallet.name.should.be.equal(keystoreMock.accounts[1].accountName)

    bip32XPublicKeyWallet.isReadOnly.should.be.equal(true)
    bip32XPublicKeyWallet.type.should.be.equal('mnemonic')
    bip32XPublicKeyWallet.customType.should.be.equal('bip32Xpub')
    bip32XPublicKeyWallet.id.should.be.equal(bip32XPublicKeyWalletId)
    bip32XPublicKeyWallet.bip32XPublicKey.should.be.equal(bip32XPublicKey2)
    bip32XPublicKeyWallet.name.should.be.equal(keystoreMock.accounts[2].accountName)
    keystore.getAddress(bip32XPublicKeyWalletId).should.be.equal(address2)

    should(addressWallet.salt).be.equal(null)
    addressWallet.isReadOnly.should.be.equal(true)
    addressWallet.id.should.be.equal(addressWalletId)
    addressWallet.customType.should.be.equal('address')
    addressWallet.address.should.be.equal(address2.toLowerCase())
    addressWallet.name.should.be.equal(keystoreMock.accounts[3].accountName)

    done()
  })

})
