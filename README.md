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

Also Keystore API provides several [utility methods](#utility-methods) for working with mnemonics / hashes / passwords.

## Get Started

```
npm install jwallet-web-keystore
```

```javascript
import keystore from 'jwallet-web-keystore'
```

### Available npm scripts:

  * `lint`: check code-style errors
  * `test`: run mocha tests
  * `clean`: clean `./lib` dir
  * `compile`: `clean`, then compile library
  * `build`: `lint` & `compile` & `test`

### Wallet properties

| Property             | Type    | Description                                                   |
| -------------------- | ------- | ------------------------------------------------------------- |
| id                   | String  | Unique ID of wallet                                           |
| type                 | String  | Type of wallet  (`mnemonic` / `address`)                      |
| name                 | String  | Wallet name                                                   |
| salt                 | String  | Salt for enforcing of password                                |
| address              | String  | Address of wallet                                             |
| customType           | String  | User-friendly type of wallet                                  |
| derivationPath       | String  | Path for derivation of keys from BIP32 Extended Key           |
| encryptionType       | String  | Type of encryption                                            |
| derivationPath       | String  | Derivation path for generating of addresses from mnemonic     |
| bip32XPublicKey      | String  | BIP32 Extended Public Key                                     |
| addressIndex         | Number  | Current index of address of `mnemonic` wallet                 |
| saltBytesCount       | Number  | Number of bytes for `salt` parameter                          |
| derivedKeyLength     | Number  | Size of derived from password key                             |
| isReadOnly           | Boolean | Read-only flag of wallet                                      |
| scryptParams         | Object  | Scrypt function params, that used for password key derivation |
| scryptParams.N       | Number  | CPU/memory cost parameter                                     |
| scryptParams.r       | Number  | The blocksize parameter                                       |
| scryptParams.p       | Number  | Parallelization parameter                                     |
| encrypted            | Object  | Container of encrypted data                                   |
| encrypted.mnemonic   | Object  | Encrypted mnemonic                                            |
| encrypted.privateKey | Object  | Encrypted private key                                         |

**Notes:**
  * `isReadOnly` - flag means that wallet can be used only for balance / transactions checking
  * `bip32XPublicKey` - `xpub...` key that used for deriving of public keys (addresses)
  * `encrypted data`(mnemonic/privateKey fields) - it is object, that looks like:
```
encrypted.mnemonic = {
  data: base64 string (encrypted),
  nonce: base64 string,
}
```

## Public API definitions

See [mocha tests](https://github.com/jibrelnetwork/jwallet-web-keystore/tree/master/test) for examples of usage.

### Methods for wallets management

#### getWallet(wallets, walletId)

##### Parameters

| Param    | Type   | Description             |
| -------- | ------ | ----------------------- |
| wallets  | Array  | List of existed wallets |
| walletId | String | Unique ID of wallet     |

##### Returns

Wallet found by its ID, otherwise exception will be thrown.

##### Example

```javascript
const wallets = keystore.createWallet(...)
const wallet = keystore.getWallet(wallets, 'JHJ23jG^*DGHj667s')
```

#### createWallet(wallets, props, password)

##### Parameters

| Param                                 | Type   | Description                                                                     |
| ------------------------------------- | ------ | ------------------------------------------------------------------------------- |
| wallets                               | Array  | List of existed wallets                                                         |
| props                                 | Object | New wallet data                                                                 |
| props.scryptParams (optional)         | Object | `scrypt` function params ([see wallet properties](#wallet-properties))          |
| props.passwordConfig (optional)       | Object | `password` config ([see password config](#wallet-properties))                   |
| props.data                            | String | main `wallet` data: address/privateKey/mnemonic/bip32XPublicKey                 |
| props.name (optional)                 | String | name of new `wallet`                                                            |
| props.derivationPath (optional)       | String | `derivation` path                                                               |
| props.encryptionType (optional)       | String | `encryption` type                                                               |
| props.saltBytesCount (optional)       | Number | size of `salt` for `password`                                                   |
| props.derivedKeyLength (optional)     | Number | size of key, `derived` from `password` with `scrypt` function                   |
| props.paddedMnemonicLength (optional) | Number | size of mnemonic phrase before encryption                                       |
| password                              | String | `wallet` password. Used only for `full access` wallets: `mnemonic`/`privateKey` |

##### Returns

List of wallets with new created one, otherwise exception will be thrown.

##### Example

```javascript
const password = 'JHJ23jG^*DGHj667s'

const walletsOne = keystore.createWallet(wallets, {
  name: 'My privateKey wallet',
  data: '0x8a02a99cc7a801da6996a2dacc406ffa5190dc9c8a02a99cc7a801da6996a2da',
}, password)

const walletsTwo = keystore.createWallet(walletsOne, {
  name: 'My address wallet',
  data: '0x8a02a99ee7a801da6996a2dacc406ffa5190dc9c',
}, password)

const walletsThree = keystore.createWallet(walletsTwo, {
  name: 'My xpub wallet',
  data: 'xpub...',
}, password)

const walletsFour = keystore.createWallet(walletsThree, {
  name: 'My mnemonic wallet',
  data: '<mnemonic phrase here>',
}, password)
```

#### removeWallet(wallets, walletId)

##### Parameters

| Param    | Type   | Description             |
| -------- | ------ | ----------------------- |
| wallets  | Array  | List of existed wallets |
| walletId | String | Unique ID of wallet     |

##### Returns

List of wallets without removed one, otherwise exception will be thrown.

##### Example

```javascript
const walletsNew = keystore.removeWallet(wallets, '110ec58a-a0f2-4ac4-8393-c977d813b8d1')
```

#### setWalletName(wallets, walletId, name)

##### Parameters

| Param    | Type   | Description             |
| -------- | ------ | ----------------------- |
| wallets  | Array  | List of existed wallets |
| walletId | String | Unique ID of wallet     |
| name     | String | New wallet name         |

##### Returns

List of wallets with new updated one, otherwise exception will be thrown.

##### Example

```javascript
const walletId = '110ec58a-a0f2-4ac4-8393-c977d813b8d1'
const name = 'New wallet name'
const walletsNew = keystore.setWalletName(wallets, walletId, name)
```

#### setAddressIndex(wallets, walletId, addressIndex)

**Note: used only for `mnemonic` wallets.**

##### Parameters

| Param                   | Type   | Description                                                    |
| ----------------------- | ------ | -------------------------------------------------------------- |
| wallets                 | Array  | List of existed wallets                                        |
| walletId                | String | Unique ID of wallet                                            |
| addressIndex (optional) | Number | Index of address to derive from `mnemonic` / `bip32XPublicKey` |

##### Returns

List of wallets with new updated one, otherwise exception will be thrown.

##### Example

```javascript
const walletsNew = keystore.setAddressIndex(wallets, walletId, addressIndex)
```

#### setDerivationPath(wallets, walletId, password, derivationPath)

**Note: used only for `mnemonic` wallets.**

##### Parameters

| Param          | Type   | Description             |
| -------------- | ------ | ----------------------- |
| wallets        | Array  | List of existed wallets |
| walletId       | String | Unique ID of wallet     |
| password       | String | Wallet password         |
| derivationPath | String | New derivation path     |

##### Returns

List of wallets with new updated one, otherwise exception will be thrown.

##### Example

```javascript
const derivationPath = 'm/44\'/61\'/0\'/0'
const walletsNew = keystore.setDerivationPath(wallets, walletId, password, derivationPath)
```

#### setPassword(wallets, walletId, password, newPassword)

**Note: not available for `read-only` wallets.**

##### Parameters

| Param       | Type   | Description             |
| ----------- | ------ | ----------------------- |
| wallets     | Array  | List of existed wallets |
| walletId    | String | Unique ID of wallet     |
| password    | String | Wallet password         |
| newPassword | String | New keystore password   |

##### Returns

List of wallets with new updated one, otherwise exception will be thrown.

##### Example

```javascript
const newPassword = 'Tw5E^g7djfd(29j'
const walletsNew = keystore.setPassword(wallets, walletId, password, newPassword)
```

#### getAddress(wallets, walletId)

##### Parameters

| Param    | Type   | Description             |
| -------- | ------ | ----------------------- |
| wallets  | Array  | List of existed wallets |
| walletId | String | Unique ID of wallet     |

##### Returns

Current address of wallet.

##### Example

```javascript
const address = keystore.getAddress(wallets, walletId)
```

#### getAddresses(wallets, walletId, startIndex, endIndex)

**Note: used only for `mnemonic` wallets.**

##### Parameters

| Param        | Type   | Description                       |
| ------------ | ------ | --------------------------------- |
| wallets      | Array  | List of existed wallets           |
| walletId     | String | Unique ID of wallet               |
| startIndex   | Number | Start index of address to derive  |
| endIndex     | Number | Finish index of address to derive |

##### Returns

List of derived addresses, otherwise exception will be thrown.

##### Example

```javascript
const startIndex = 3
const endIndex = 10
const addresses = keystore.getAddressesFromMnemonic(wallets, walletId, startIndex, endIndex)
```

#### getPrivateKey(wallets, walletId, password)

**Note: not available for `read-only` wallets.**

##### Parameters

| Param    | Type   | Description             |
| -------- | ------ | ----------------------- |
| wallets  | Array  | List of existed wallets |
| walletId | String | Unique ID of wallet     |
| password | String | Wallet password         |

##### Returns

Decrypted private key, otherwise exception will be thrown.

##### Example

```javascript
const privateKey = keystore.getPrivateKey(wallets, walletId, password)
```

#### getMnemonic(wallets, walletId, password)

**Note: used only for `full-access` `mnemonic` wallets.**

##### Parameters

| Param    | Type   | Description             |
| -------- | ------ | ----------------------- |
| wallets  | Array  | List of existed wallets |
| walletId | String | Unique ID of wallet     |
| password | String | Wallet password         |

##### Returns

Decrypted mnemonic, otherwise exception will be thrown.

##### Example

```javascript
const mnemonic = keystore.getMnemonic(wallets, walletId, password)
```

#### getWalletData(wallets, walletId, password)

**Note: password required only for `full-access` wallets.**

##### Parameters

| Param    | Type   | Description             |
| -------- | ------ | ----------------------- |
| wallets  | Array  | List of existed wallets |
| walletId | String | Unique ID of wallet     |
| password | String | Wallet password         |

#### Returns

Wallet with decrypted data, otherwise exception will be thrown.

##### Example

```javascript
const walletData = keystore.getWalletData(wallets, walletId, password)
```

#### serialize()

##### Returns

Serialized keystore data for backup.

##### Example

```javascript
const keystoreSerializedData = keystore.serialize(wallets)
```

#### deserialize(backupData)

##### Parameters

| Param      | Type   | Description              |
| ---------- | ------ | ------------------------ |
| backupData | String | Keystore serialized data |

##### Example

```javascript
const backupData = '{"wallets":[{"type":"mnemonic","id":"2e820ddb-a9ce-43e1-b7ec-dbed59eec7e9",...'
const keystoreDeserializedData = keystore.deserialize(backupData)
```

### Static methods

#### testPassword(password, passwordConfig)

| Param                               | Type   | Default | Description                |
| ----------------------------------- | ------ | ------- | -------------------------- |
| password                            | String |         | Wallet password            |
| passwordConfig (optional)           | Object | {}      | Password options container |
| passwordConfig.minLength (optional) | Number | 10      | Min length for password    |
| passwordConfig.minLength (optional) | Number | 128     | Max length for password    |

##### Returns

Object that contains following fields:

  * errors - error messages array
  * failedTests - failed test names array
  * passedTests - passed test names array

##### Example

```javascript
const result = keystore.testPassword('JHJ23jG^*DGHj667s')
```

#### generateMnemonic(entropy, randomBufferLength)

| Param                         | Type   | Description                                         |
| ----------------------------- | ------ | --------------------------------------------------- |
| entropy (optional)            | String | Entropy for mnemonic initialisation (see [new Mnemonic](https://bitcore.io/api/mnemonic#new_Mnemonic_new)) |
| randomBufferLength (optional) | Number | Buffer length (if `entropy` param is used) |

##### Returns

Mnemonic - string with 12 English words splited by space.

##### Example

```javascript
const mnemonic = keystore.generateMnemonic()
```

#### checkMnemonicValid(mnemonic)

##### Parameters

| Param    | Type   | Description       |
| -------- | ------ | ----------------- |
| mnemonic | String | Mnemonic to check |

##### Returns

`true` if mnemonic is valid and `false` otherwise.

##### Example

```javascript
const mnemonic = 'come average primary sunny profit eager toy pulp struggle hazard tourist round'
const isValid = keystore.checkMnemonicValid(mnemonic) // true
```

#### checkBip32XPublicKeyValid(bip32XPublicKey)

| Param           | Type   | Description               |
| --------------- | ------ | ------------------------- |
| bip32XPublicKey | String | BIP32 Extended Public Key |

##### Returns

`true` if bip32XPublicKey is valid and `false` otherwise.

##### Example

```javascript
const isValid = keystore.checkBip32XPublicKeyValid('xpub...')
```

#### checkAddressValid(address)

| Param     | Type   | Description                                         |
| --------- | ------ | --------------------------------------------------- |
| address   | String | Address to check. Accepts checksummed addresses too |

##### Returns

`true` if address is valid and `false` otherwise.

##### Example

```javascript
const isValid = keystore.checkAddressValid('0x8a02a99ee7a801da6996a2dacc406ffa5190dc9c')
```

#### checkChecksumAddressValid(address)

| Param     | Type   | Description      |
| --------- | ------ | ---------------- |
| address   | String | Address to check |

##### Returns

`true` if address contains checksum and `false` otherwise.

##### Example

```javascript
const isValid = keystore.checkChecksumAddressValid('0x8a02a99ee7a801da6996a2dacc406ffa5190dc9c')
```

#### checkPrivateKeyValid(privateKey)

| Param      | Type   | Description          |
| ---------- | ------ | -------------------- |
| privateKey | String | Private Key to check |

##### Returns

`true` if privateKey is valid and `false` otherwise.

##### Example

```javascript
const pk = '0xa7fcb4efc392d2c8983cbfe64063f994f85120e60843407af95907d905d0dc9f'
const isValid = keystore.checkPrivateKeyValid(pk)
```

#### checkDerivationPathValid(derivationPath)

| Param          | Type   | Description     |
| -------------- | ------ | --------------- |
| derivationPath | String | Derivation path |

##### Returns

`true` if derivationPath is valid and `false` otherwise.

##### Example

```javascript
const isValid = keystore.checkDerivationPathValid("m/44'/60'/0'/0")
```
