# Keystore

Library for ethereum blockchain accounts management.

## About

Keystore can hold `read only` / `full access` accounts of two types:
* Address / PrivateKey
* Mnemonic

Also Keystore API provides some utility methods for working with mnemonics / hashes / passwords.

## Get Started

```
npm install keystore
```

```javascript
const Keystore = require('keystore')

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
| address              | String  | Address of account (current address if type is `mnemonic`)        |
| bip32XPublicKey      | String  | BIP32 Extended Public Key                                         |
| encrypted            | Object  | Container of encrypted data                                       |
| encrypted.privateKey | Object  | Encrypted private key (current private key if type is `mnemonic`) |
| encrypted.mnemonic   | Object  | Encrypted mnemonic                                                |
| encrypted.hdPath     | Object  | Encrypted HD private key parent                                   |

#### Notes:

  * `isReadOnly` - flag means that account can be used only for balance / transactions checking
  * `bip32XPublicKey` - `xpub...` key that used for deriving of public keys (addresses)
  * `encrypted.hdPath` - `xprv...` key that used for deriving of private keys

## Public API definitions

See [mocha tests](https://github.com/jibrelnetwork/keystore/tree/master/test) for examples of usage.

### new Keystore(props)

Instantiates `Keystore` object with provided `props`.

##### Parameters

| Param                          | Type   | Default                    | Description                   |
| ------------------------------ | ------ | -------------------------- | ----------------------------- |
| props                          | Object | {}                         | Constructor properties        |
| props.accounts                 | Array  | []                         | Array of accounts             |
| props.defaultDerivationPath    | String | "m/44'/60'/0'/0"           | Default derivation path for new `Mnemonic` accounts |
| props.defaultEncryptionType    | String | 'nacl.secretbox'           | Default encryption type. Currently `nacl.secretbox` is only one supported |
| props.addressesCountToGenerate | Number | 3                          | Count of addresses to generate from mnemonic per one page / iteration |
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

#### setDerivationPath(password, accountId, newDerivationPath)

##### Parameters

| Param             | Type   | Description          |
| ----------------- | ------ | -------------------- |
| password          | String | Keystore password    |
| accountId         | String | Unique ID of account |
| newDerivationPath | String | New derivation path  |

Note: default derivation path that will be assigned to all new created accounts can be managed by `defaultDerivationPath` constructor parameter.

##### Returns

Updated account.

##### Example

```javascript
const updatedAccount = keystore.setDerivationPath('JHJ23jG^*DGHj667s', '110ec58a-a0f2-4ac4-8393-c977d813b8d1', "m/44'/61'/0'/0")
```

#### getPrivateKey(password, accountId)

##### Parameters

| Param     | Type   | Description          |
| --------- | ------ | -------------------- |
| password  | String | Keystore password    |
| accountId | String | Unique ID of account |

##### Returns

Decrypted private key.

##### Example

```javascript
const privateKey = keystore.getPrivateKey('JHJ23jG^*DGHj667s', '110ec58a-a0f2-4ac4-8393-c977d813b8d1')
```

#### setAddress(password, accountId, addressIndex)

Note: used only for `mnemonic` accounts.

##### Parameters

| Param        | Type   | Description                                                    |
| ------------ | ------ | -------------------------------------------------------------- |
| password     | String | Keystore password                                              |
| accountId    | String | Unique ID of account                                           |
| addressIndex | String | Index of address to derive from `mnemonic` / `bip32XPublicKey` |

##### Returns

Updated account.

##### Example

```javascript
const updatedAccount = keystore.setAddress('JHJ23jG^*DGHj667s', '110ec58a-a0f2-4ac4-8393-c977d813b8d1', 5)
```

#### getAddressesFromMnemonic(password, accountId, iteration)

Note: used only for `mnemonic` accounts.

##### Parameters

| Param     | Type   | Description                                                              |
| --------- | ------ | ------------------------------------------------------------------------ |
| password  | String | Keystore password                                                        |
| accountId | String | Unique ID of account                                                     |
| iteration | Number | Iteration index (aka page for pagination) to generate bunch of addresses |

Note: addresses count to generate per one iteration can be managed by `addressesCountToGenerate` constructor parameter.

##### Returns

List of generated addresses.

##### Example

```javascript
const addresses = keystore.getAddressesFromMnemonic('JHJ23jG^*DGHj667s', '110ec58a-a0f2-4ac4-8393-c977d813b8d1', 3)
```

#### getMnemonic(password, accountId)

Note: used only for `mnemonic` accounts.

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

#### serialize(password)

##### Parameters

| Param    | Type   | Description          |
| -------- | ------ | -------------------- |
| password | String | Keystore password    |

##### Returns

Serialized keystore data for backup.

##### Example

```javascript
const keystoreSerializedData = keystore.serialize('JHJ23jG^*DGHj667s')
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
### Static methods

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

#### generateMnemonic(entropy, randomBufferLength)

| Param               | Type   | Description                                         |
| ------------------- | ------ | --------------------------------------------------- |
| entropy             | String | Entropy for mnemonic initialisation (see [new Mnemonic](https://bitcore.io/api/mnemonic#new_Mnemonic_new)) |
| randomBufferLength  | Number | Buffer length (if `entropy` param is used) |

##### Returns

Mnemonic - 12 English words splited by space.

##### Example

```javascript
const isValid = Keystore.generateMnemonic()
```

#### isHashStringValid(hash, hashLength)

| Param      | Type   | Description                                 |
| ---------- | ------ | ------------------------------------------- |
| hash       | String | Hash string to check                        |
| hashLength | Number | Hash length (should be equal `hash.length`) |

##### Returns

`true` if hash is valid and `false` otherwise.

##### Example

```javascript
const isValid = Keystore.isHashStringValid('0x8a02a99ee7a801da6996a2dacc406ffa5190dc9c', 42)
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
  * failedTests - failed tests count
  * passedTests - passed tests count

##### Example

```javascript
const result = Keystore.testPassword('JHJ23jG^*DGHj667s')
console.log(result) // { errors: [], failedTests: 0, passedTests: 7 }
```