# jwallet-web-keystore

Library for ethereum blockchain wallets management.

<p align="center">
<a href="https://www.npmjs.com/package/jwallet-web-keystore"><img src="https://img.shields.io/npm/v/jwallet-web-keystore.svg?style=flat-square" alt="NPM version"></a>
<a href="https://www.npmjs.com/package/jwallet-web-keystore"><img src="https://img.shields.io/npm/dt/jwallet-web-keystore.svg?style=flat-square" alt="NPM downloads"></a>
<a href="https://www.npmjs.com/package/jwallet-web-keystore"><img src="https://img.shields.io/npm/l/jwallet-web-keystore.svg?style=flat-square" alt="MIT License"></a>
<a href="https://www.npmjs.com/package/jwallet-web-keystore"><img src="https://img.shields.io/david/jibrelnetwork/jwallet-web-keystore.svg?style=flat-square" alt="Dependecies"></a>
</p>

## About

Keystore can hold `read only` / `full access` wallets of two types:
* `privateKey` / `address`
* `mnemonic` / `bip32XPublicKey`

Also Keystore API provides several [utility methods](#static-methods) for working with mnemonics / hashes / passwords.

## Get Started

```
npm install jwallet-web-keystore
```

```javascript
const Keystore = require('jwallet-web-keystore')

const keystore = new Keystore(props)
```

### Available npm scripts:

  * `lint`: check code-style errors
  * `test`: run mocha tests
  * `clean`: clean `./lib` dir
  * `compile`: `clean`, then compile library
  * `build`: `lint` & `compile` & `test`

### Wallet properties

| Property             | Type    | Description                                               |
| -------------------- | ------- | --------------------------------------------------------- |
| id                   | String  | Unique ID of wallet                                       |
| type                 | String  | Type of wallet  (`mnemonic` / `address`)                  |
| name                 | String  | Wallet name                                               |
| salt                 | String  | Salt for enforcing of password                            |
| address              | String  | Address of wallet                                         |
| customType           | String  | User-friendly type of wallet                              |
| isReadOnly           | Boolean | Read-only flag of wallet                                  |
| addressIndex         | Number  | Current index of address of `mnemonic` wallet             |
| derivationPath       | String  | Derivation path for generating of addresses from mnemonic |
| bip32XPublicKey      | String  | BIP32 Extended Public Key                                 |
| encrypted            | Object  | Container of encrypted data                               |
| encrypted.privateKey | Object  | Encrypted private key                                     |
| encrypted.mnemonic   | Object  | Encrypted mnemonic                                        |

**Notes:**
  * `isReadOnly` - flag means that wallet can be used only for balance / transactions checking
  * `bip32XPublicKey` - `xpub...` key that used for deriving of public keys (addresses)

## Public API definitions

See [mocha tests](https://github.com/jibrelnetwork/jwallet-web-keystore/tree/master/test) for examples of usage.

### new Keystore(props)

Instantiates `Keystore` object with provided `props`.

##### Parameters

| Param                          | Type   | Default                    | Description                   |
| ------------------------------ | ------ | -------------------------- | ----------------------------- |
| props                          | Object | {}                         | Constructor properties        |
| props.defaultDerivationPath    | String | "m/44'/60'/0'/0"           | Default derivation path for new `Mnemonic` wallets |
| props.defaultEncryptionType    | String | 'nacl.secretbox'           | Default encryption type. Currently `nacl.secretbox` is only one supported |
| props.paddedMnemonicLength     | Number | 120                        | Mnemonic will be padded left with this size before encryption |
| props.saltByteCount            | Number | 32                         | Count of bytes of generated salt for password strength |
| props.scryptParams             | Object | { N: 2 ** 18, r: 8, p: 1 } | Scrypt params for key deriving |
| props.derivedKeyLength         | String | 32                         | Derived key length            |
| props.passwordConfig           | Object | {}                         | Options to test password strength |

##### Returns

New instance of `Keystore` class.

##### Example

```javascript
const keystore = new Keystore({ defaultDerivationPath: "m/44'/61'/0'/0" })
```

### Instance methods

#### getWallets()

##### Returns

Wallets list presented in keystore.

##### Example

```javascript
const wallets = keystore.getWallets()
```

#### getWallet(walletId)

##### Parameters

Wallet ID.

##### Returns

Wallet found by its ID.

##### Example

```javascript
const wallet = keystore.getWallet('JHJ23jG^*DGHj667s')
```

#### createWallet(props)

##### Parameters

wallet properties([Wallet properties](#wallet-properties)):
* `type`
* `name`
* `address`
* `mnemonic`
* `isReadOnly`
* `privateKey`
* `derivationPath`
* `bip32XPublicKey`

##### Returns

Unique ID of created wallet

##### Example

```javascript
const walletId = keystore.createWallet({
  type: 'address',
  name: 'My wallet',
  isReadonly: false,
  password: 'JHJ23jG^*DGHj667s',
  privateKey: '0x8a02a99cc7a801da6996a2dacc406ffa5190dc9c8a02a99cc7a801da6996a2da',
})
```

#### removeWallet(walletId)

##### Parameters

| Param    | Type   | Description         |
| -------- | ------ | ------------------- |
| walletId | String | Unique ID of wallet |

##### Returns

Removed wallet data.

##### Example

```javascript
const removedWallet = keystore.removeWallet('110ec58a-a0f2-4ac4-8393-c977d813b8d1') // data
```

#### removeWallets()

##### Example

```javascript
keystore.removeWallets() // ok, wallets were removed
```

#### setWalletName(walletId, newName)

##### Parameters

| Param    | Type   | Description         |
| -------- | ------ | ------------------- |
| walletId | String | Unique ID of wallet |
| newName  | String | New wallet name     |

##### Returns

Updated wallet.

##### Example

```javascript
const updatedWallet = keystore.setWalletName('110ec58a-a0f2-4ac4-8393-c977d813b8d1', 'New wallet name')
```

#### getPrivateKey(password, walletId)

##### Parameters

| Param    | Type   | Description         |
| -------- | ------ | ------------------- |
| password | String | Wallet password     |
| walletId | String | Unique ID of wallet |

##### Returns

Decrypted private key.

##### Example

```javascript
const privateKey = keystore.getPrivateKey('JHJ23jG^*DGHj667s', '110ec58a-a0f2-4ac4-8393-c977d813b8d1')
```

#### setDerivationPath(password, walletId, newDerivationPath)

**Note: used only for `mnemonic` wallets.**

##### Parameters

| Param             | Type   | Description         |
| ----------------- | ------ | ------------------- |
| password          | String | Wallet password     |
| walletId          | String | Unique ID of wallet |
| newDerivationPath | String | New derivation path |

**Note: default derivation path that will be assigned to all new created wallets can be managed by `defaultDerivationPath` constructor parameter.**

##### Returns

Updated wallet.

##### Example

```javascript
const updatedWallet = keystore.setDerivationPath('JHJ23jG^*DGHj667s', '110ec58a-a0f2-4ac4-8393-c977d813b8d1', "m/44'/61'/0'/0")
```

#### getMnemonic(password, walletId)

**Note: used only for `mnemonic` wallets.**

##### Parameters

| Param    | Type   | Description         |
| -------- | ------ | ------------------- |
| password | String | Wallet password     |
| walletId | String | Unique ID of wallet |

##### Returns

Decrypted mnemonic.

##### Example

```javascript
const mnemonic = keystore.getMnemonic('JHJ23jG^*DGHj667s', '110ec58a-a0f2-4ac4-8393-c977d813b8d1')
```

#### getAddressesFromMnemonic(walletId, iteration, limit)

**Note: used only for `mnemonic` wallets.**

##### Parameters

| Param     | Type   | Description                                                              |
| --------- | ------ | ------------------------------------------------------------------------ |
| walletId  | String | Unique ID of wallet                                                      |
| iteration | Number | Iteration index (aka page for pagination) to generate bunch of addresses |
| limit     | Number | Count of addresses to generate from mnemonic per one page / iteration    |

##### Returns

List of generated addresses.

##### Example

```javascript
const addresses = keystore.getAddressesFromMnemonic('110ec58a-a0f2-4ac4-8393-c977d813b8d1', 3, 10)
```

#### getAddress(walletId, addressIndex)

##### Parameters

| Param    | Type   | Description         |
| -------- | ------ | ------------------- |
| walletId | String | Unique ID of wallet |

##### Returns

Current address of wallet.

##### Example

```javascript
const address = keystore.getAddress('110ec58a-a0f2-4ac4-8393-c977d813b8d1')
```

#### setAddressIndex(walletId, addressIndex)

**Note: used only for `mnemonic` wallets.**

##### Parameters

| Param        | Type   | Description                                                    |
| ------------ | ------ | -------------------------------------------------------------- |
| walletId     | String | Unique ID of wallet                                            |
| addressIndex | String | Index of address to derive from `mnemonic` / `bip32XPublicKey` |

##### Returns

Updated wallet.

##### Example

```javascript
const updatedWallet = keystore.setAddress('110ec58a-a0f2-4ac4-8393-c977d813b8d1', 5)
```

#### serialize()

##### Returns

Serialized keystore data for backup.

##### Example

```javascript
const keystoreSerializedData = keystore.serialize()
```

#### deserialize(backupData)

##### Parameters

| Param      | Type   | Description              |
| ---------- | ------ | ------------------------ |
| backupData | String | Keystore serialized data |

##### Returns

Deserialized keystore data for restoring of backup.

##### Example

```javascript
const backupData = '{"wallets":[{"type":"mnemonic","id":"2e820ddb-a9ce-43e1-b7ec-dbed59eec7e9",...'
const keystoreDeserializedData = keystore.deserialize(backupData)
```

#### getDecryptedWallet(password, walletId)

##### Parameters

| Param    | Type   | Description         |
| -------- | ------ | ------------------- |
| password | String | Wallet password     |
| walletId | String | Unique ID of wallet |

#### Returns

Wallet with decrypted data.

##### Example

```javascript
const decryptedWallet = keystore.getDecryptedWallets('JHJ23jG^*DGHj667s', '110ec58a-a0f2-4ac4-8393-c977d813b8d1')
```

#### setPassword(password, newPassword, walletId)

##### Parameters

| Param       | Type   | Description           |
| ----------- | ------ | --------------------- |
| password    | String | Wallet password       |
| newPassword | String | New keystore password |
| walletId    | String | Unique ID of wallet   |

##### Example

```javascript
keystore.setPassword('JHJ23jG^*DGHj667s', 'Tw5E^g7djfd(29j', '110ec58a-a0f2-4ac4-8393-c977d813b8d1')
```

### Static methods

#### generateMnemonic(entropy, randomBufferLength)

| Param               | Type   | Description                                         |
| ------------------- | ------ | --------------------------------------------------- |
| entropy             | String | Entropy for mnemonic initialisation (see [new Mnemonic](https://bitcore.io/api/mnemonic#new_Mnemonic_new)) |
| randomBufferLength  | Number | Buffer length (if `entropy` param is used) |

##### Returns

Mnemonic - 12 English words splited by space.

##### Example

```javascript
const mnemonic = Keystore.generateMnemonic()
```

#### isMnemonicValid(mnemonic)

##### Parameters

| Param    | Type   | Description       |
| -------- | ------ | ----------------- |
| mnemonic | String | Mnemonic to check |

##### Returns

`true` if mnemonic is valid and `false` otherwise.

##### Example

```javascript
const mnemonic = 'come average primary sunny profit eager toy pulp struggle hazard tourist round'
const isValid = Keystore.isMnemonicValid(mnemonic) // true
```

#### isBip32XPublicKeyValid(bip32XPublicKey)

| Param           | Type   | Description               |
| --------------- | ------ | ------------------------- |
| bip32XPublicKey | String | BIP32 Extended Public Key |

##### Returns

`true` if bip32XPublicKey is valid and `false` otherwise.

##### Example

```javascript
const isValid = Keystore.isBip32XPublicKeyValid('xpub...')
```

#### isAddressValid(address)

| Param     | Type   | Description                                         |
| --------- | ------ | --------------------------------------------------- |
| address   | String | Address to check. Accepts checksummed addresses too |

##### Returns

`true` if address is valid and `false` otherwise.

##### Example

```javascript
const isValid = Keystore.isAddressValid('0x8a02a99ee7a801da6996a2dacc406ffa5190dc9c')
```

#### isPrivateKeyValid(privateKey)

| Param      | Type   | Description          |
| ---------- | ------ | -------------------- |
| privateKey | String | Private Key to check |

##### Returns

`true` if privateKey is valid and `false` otherwise.

##### Example

```javascript
const pk = '0xa7fcb4efc392d2c8983cbfe64063f994f85120e60843407af95907d905d0dc9f'
const isValid = Keystore.isPrivateKeyValid(pk)
```

#### isDerivationPathValid(derivationPath)

| Param          | Type   | Description     |
| -------------- | ------ | --------------- |
| derivationPath | String | Derivation path |

##### Returns

`true` if derivationPath is valid and `false` otherwise.

##### Example

```javascript
const isValid = Keystore.isDerivationPathValid("m/44'/60'/0'/0")
```

#### testPassword(password, passwordConfig)

| Param                    | Type   | Default | Description                |
| ------------------------ | ------ | ------- | -------------------------- |
| password                 | String |         | Wallet password            |
| passwordConfig           | Object | {}      | Password options container |
| passwordConfig.minLength | Number | 10      | Min length for password    |
| passwordConfig.minLength | Number | 128     | Max length for password    |

##### Returns

Object that contains following fields:

  * errors - error messages array
  * failedTests - failed test names array
  * passedTests - passed test names array

##### Example

```javascript
const result = Keystore.testPassword('JHJ23jG^*DGHj667s')
```
