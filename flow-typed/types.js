declare type Address = string
declare type Addresses = Array<Address>

declare type WalletType = 'address' | 'mnemonic'
declare type WalletCustomType = WalletType | 'bip32Xpub' | 'privateKey'

declare type WalletEncryptedData = {
  +mnemonic: ?EncryptedData,
  +privateKey: ?EncryptedData,
}

declare type Wallet = {
  +scryptParams: ?ScryptParams,
  +encrypted: WalletEncryptedData,
  +id: string,
  +name: string,
  +salt: ?string,
  +type: WalletType,
  +address: ?string,
  +derivationPath: ?string,
  +encryptionType: ?string,
  +bip32XPublicKey: ?string,
  +customType: WalletCustomType,
  +addressIndex: ?number,
  +saltBytesCount: ?number,
  +derivedKeyLength: ?number,
  +isReadOnly: boolean,
}

declare type WalletUpdatedData = {
  +encrypted?: WalletEncryptedData,
  +scryptParams?: ?ScryptParams,
  +name?: string,
  +salt?: ?string,
  +derivationPath?: ?string,
  +encryptionType?: ?string,
  +bip32XPublicKey?: ?string,
  +addressIndex?: ?number,
  +saltBytesCount?: ?number,
  +derivedKeyLength?: ?number,
}

declare type WalletNewData = {
  +passwordConfig: {
    minLength?: number,
    maxLength?: number,
  },
  +scryptParams?: ScryptParams,
  +data: string,
  +name: string,
  +password: string,
  +derivationPath?: string,
  +encryptionType?: string,
  +saltBytesCount?: number,
  +derivedKeyLength?: number,
  +paddedMnemonicLength?: number,
}

declare type WalletData = {
  +scryptParams: ScryptParams,
  +id: string,
  +data: string,
  +name: string,
  +derivationPath: string,
  +encryptionType: string,
  +saltBytesCount: number,
  +derivedKeyLength: number,
  +paddedMnemonicLength: number,
}

declare type WalletDecryptedData = {
  +id: string,
  +name: string,
  +address: string,
  +mnemonic: string,
  +privateKey: string,
  +type: WalletCustomType,
  +readOnly: 'yes' | 'no',
  +bip32XPublicKey: string,
}

declare type Wallets = Array<Wallet>

declare type Backup = {
  +salt: string,
  +version: string,
  +wallets?: ?Wallets,
  +accounts?: ?Accounts,
}

declare type PasswordConfig = {
  +minLength: number,
  +maxLength: number,
}

declare type PasswordResult = {
  +errors: Array<string>,
  +failedTests: Array<string>,
  +passedTests: Array<string>,
}

declare type SetPasswordOptions = {
  scryptParams: ScryptParams,
  salt: string,
  encryptionType: string,
  saltBytesCount: number,
  derivedKeyLength: number,
}

declare type ScryptParams = {
  +N: number,
  +r: number,
  +p: number,
}

type EncryptedData = {
  +data: string,
  +nonce: string,
}

/////////////////////////////////////////
// Legacy
/////////////////////////////////////////

declare type Account = {
  +encrypted: ?{
    +mnemonic: ?string,
    +privateKey: ?string,
  },
  +id: string,
  +address: ?string,
  +type: WalletType,
  +accountName: string,
  +derivationPath: ?string,
  +bip32XPublicKey: ?string,
  +addressIndex: ?number,
  +isReadOnly: boolean,
}

declare type Accounts = Array<Account>
