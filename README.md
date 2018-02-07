# jwallet-web-keystore

Library for ethereum blockchain accounts management.

<p align="center">
<a href="https://www.npmjs.com/package/jwallet-web-keystore"><img src="https://img.shields.io/npm/v/jwallet-web-keystore.svg?style=flat-square" alt="NPM version"></a>
<a href="https://www.npmjs.com/package/jwallet-web-keystore"><img src="https://img.shields.io/npm/dt/jwallet-web-keystore.svg?style=flat-square" alt="NPM downloads"></a>
<a href="https://www.npmjs.com/package/jwallet-web-keystore"><img src="https://img.shields.io/npm/l/jwallet-web-keystore.svg?style=flat-square" alt="MIT License"></a>
<a href="https://www.npmjs.com/package/jwallet-web-keystore"><img src="https://img.shields.io/david/jibrelnetwork/jwallet-web-keystore.svg?style=flat-square" alt="Dependecies"></a>
</p>

## About

Keystore can hold `read only` / `full access` accounts of two types:
* Address / PrivateKey
* Mnemonic

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

### Account properties

| Property             | Type    | Description                                                       |
| -------------------- | ------- | ----------------------------------------------------------------- |
| id                   | String  | Unique ID of account                                              |
| type                 | String  | Type of account (`mnemonic` / `address`)                          |
| accountName          | String  | Account name                                                      |
| derivationPath       | String  | Derivation path for generating of addresses from mnemonic         |
| isReadOnly           | Boolean | Read-only flag of account                                         |
| address              | String  | Address of account                                                |
| addressIndex         | Number  | Current index of address of `mnemonic` account                    |
| bip32XPublicKey      | String  | BIP32 Extended Public Key                                         |
| encrypted            | Object  | Container of encrypted data                                       |
| encrypted.privateKey | Object  | Encrypted private key                                             |
| encrypted.mnemonic   | Object  | Encrypted mnemonic                                                |

**Notes:**
  * `isReadOnly` - flag means that account can be used only for balance / transactions checking
  * `bip32XPublicKey` - `xpub...` key that used for deriving of public keys (addresses)

## Public API definitions

See [mocha tests](https://github.com/jibrelnetwork/keystore/tree/master/test) for examples of usage.

### new Keystore(props)

Instantiates `Keystore` object with provided `props`.

##### Parameters

| Param                          | Type   | Default                    | Description                   |
| ------------------------------ | ------ | -------------------------- | ----------------------------- |
| props                          | Object | {}                         | Constructor properties        |
| props.defaultDerivationPath    | String | "m/44'/60'/0'/0"           | Default derivation path for new `Mnemonic` accounts |
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

#### getAccounts()

##### Returns

Accounts list presented in keystore.

##### Example

```javascript
const accounts = keystore.getAccounts()
```

#### getAccount(props)

##### Parameters

account properties object ([Account properties](#account-properties)).

**Note: all properties are optional except of `id`.**

##### Returns

Accounts list presented in keystore.

##### Example

```javascript
const accounts = keystore.getAccounts()
```

#### createAccount(props)

##### Parameters

account properties with except of `id` & `encrypted` ([Account properties](#account-properties))

##### Returns

Unique ID of created account

##### Example

```javascript
const accountId = keystore.createAccount({
  password: 'JHJ23jG^*DGHj667s',
  type: 'address',
  privateKey: '0x8a02a99cc7a801da6996a2dacc406ffa5190dc9c8a02a99cc7a801da6996a2da',
  accountName: 'My account',
})
```

#### removeAccount(accountId)

##### Parameters

| Param     | Type   | Description          |
| --------- | ------ | -------------------- |
| accountId | String | Unique ID of account |

##### Returns

`true` if removed, otherwise `false`.

##### Example

```javascript
const result = keystore.removeAccount('110ec58a-a0f2-4ac4-8393-c977d813b8d1') // true
```

#### removeAccounts([password])

##### Parameters

| Param     | Type   | Description                                  |
| --------- | ------ | -------------------------------------------- |
| password  | String | Keystore password. The parameter is optional |

##### Example

```javascript
keystore.removeAccounts('JHJ23jG^*DGHj667s') // all keystore accounts were removed
keystore.removeAccounts('123') // failed, password is invalid
keystore.removeAccounts() // ok, accounts were removed
```

#### setAccountName(accountId, newName)

##### Parameters

| Param     | Type   | Description          |
| --------- | ------ | -------------------- |
| accountId | String | Unique ID of account |
| newName   | String | New account name     |

##### Returns

Updated account.

##### Example

```javascript
const updatedAccount = keystore.setAccountName('110ec58a-a0f2-4ac4-8393-c977d813b8d1', 'New account name')
```

#### getPrivateKey(password, accountId, addressIndex)

##### Parameters

| Param        | Type   | Description                                                          |
| ------------ | ------ | -------------------------------------------------------------------- |
| password     | String | Keystore password                                                    |
| accountId    | String | Unique ID of account                                                 |
| addressIndex | Number | Index of address (private key) to derive from `mnemonic` (default 0) |

##### Returns

Decrypted private key.

##### Example

```javascript
const privateKey = keystore.getPrivateKey('JHJ23jG^*DGHj667s', '110ec58a-a0f2-4ac4-8393-c977d813b8d1')
```

#### setDerivationPath(password, accountId, newDerivationPath)

**Note: used only for `mnemonic` accounts.**

##### Parameters

| Param             | Type   | Description          |
| ----------------- | ------ | -------------------- |
| password          | String | Keystore password    |
| accountId         | String | Unique ID of account |
| newDerivationPath | String | New derivation path  |

**Note: default derivation path that will be assigned to all new created accounts can be managed by `defaultDerivationPath` constructor parameter.**

##### Returns

Updated account.

##### Example

```javascript
const updatedAccount = keystore.setDerivationPath('JHJ23jG^*DGHj667s', '110ec58a-a0f2-4ac4-8393-c977d813b8d1', "m/44'/61'/0'/0")
```

#### getMnemonic(password, accountId)

**Note: used only for `mnemonic` accounts.**

##### Parameters

| Param     | Type   | Description          |
| --------- | ------ | -------------------- |
| password  | String | Keystore password    |
| accountId | String | Unique ID of account |

##### Returns

Decrypted mnemonic.

##### Example

```javascript
const mnemonic = keystore.getMnemonic('JHJ23jG^*DGHj667s', '110ec58a-a0f2-4ac4-8393-c977d813b8d1')
```

#### getAddressesFromMnemonic(accountId, iteration, limit)

**Note: used only for `mnemonic` accounts.**

##### Parameters

| Param     | Type   | Description                                                              |
| --------- | ------ | ------------------------------------------------------------------------ |
| accountId | String | Unique ID of account                                                     |
| iteration | Number | Iteration index (aka page for pagination) to generate bunch of addresses |
| limit     | Number | Count of addresses to generate from mnemonic per one page / iteration    |

##### Returns

List of generated addresses.

##### Example

```javascript
const addresses = keystore.getAddressesFromMnemonic('110ec58a-a0f2-4ac4-8393-c977d813b8d1', 3, 10)
```

#### getAddressFromMnemonic(accountId, addressIndex)

**Note: used only for `mnemonic` accounts.**

##### Parameters

| Param        | Type   | Description                                                    |
| ------------ | ------ | -------------------------------------------------------------- |
| accountId    | String | Unique ID of account                                           |
| addressIndex | String | Index of address to derive from `mnemonic` / `bip32XPublicKey` |

##### Returns

Derived by index address.

##### Example

```javascript
const address = keystore.getAddressFromMnemonic('110ec58a-a0f2-4ac4-8393-c977d813b8d1', 5)
```

#### setAddressIndex(accountId, addressIndex)

**Note: used only for `mnemonic` accounts.**

##### Parameters

| Param        | Type   | Description                                                    |
| ------------ | ------ | -------------------------------------------------------------- |
| accountId    | String | Unique ID of account                                           |
| addressIndex | String | Index of address to derive from `mnemonic` / `bip32XPublicKey` |

##### Returns

Updated account.

##### Example

```javascript
const updatedAccount = keystore.setAddress('110ec58a-a0f2-4ac4-8393-c977d813b8d1', 5)
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
const backupData = '{"accounts":[{"type":"mnemonic","id":"2e820ddb-a9ce-43e1-b7ec-dbed59eec7e9",...'
const keystoreDeserializedData = keystore.deserialize(backupData)
```

#### getDecryptedAccounts(password)

##### Parameters

| Param    | Type   | Description       |
| -------- | ------ | ----------------- |
| password | String | Keystore password |

#### Returns

Accounts with decrypted data.

##### Example

```javascript
const decryptedAccounts = keystore.getDecryptedAccounts('JHJ23jG^*DGHj667s')
```

#### setPassword(password, newPassword)

##### Parameters

| Param        | Type   | Description              |
| ------------ | ------ | ------------------------ |
| password     | String | Keystore password        |
| newPassword  | String | New keystore password    |

##### Example

```javascript
keystore.setPassword('JHJ23jG^*DGHj667s', 'Tw5E^g7djfd(29j')
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

#### isValidAddress(address)

| Param     | Type   | Description                                         |
| --------- | ------ | --------------------------------------------------- |
| address   | String | Address to check. Accepts checksummed addresses too |

##### Returns

`true` if address is valid and `false` otherwise.

##### Example

```javascript
const isValid = Keystore.isValidAddress('0x8a02a99ee7a801da6996a2dacc406ffa5190dc9c')
```

#### isValidPrivateKey(privateKey)

| Param      | Type   | Description          |
| ---------- | ------ | -------------------- |
| privateKey | String | Private Key to check |

##### Returns

`true` if privateKey is valid and `false` otherwise.

##### Example

```javascript
const pk = '0xa7fcb4efc392d2c8983cbfe64063f994f85120e60843407af95907d905d0dc9f'
const isValid = Keystore.isValidPrivateKey(pk)
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
| password                 | String |         | Keystore password          |
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
