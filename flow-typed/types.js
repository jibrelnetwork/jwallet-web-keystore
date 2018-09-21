declare type Address = string
declare type Addresses = Array<Address>

declare type Network = string | number

declare type WalletType = 'address' | 'mnemonic'
declare type WalletCustomType = WalletType | 'bip32Xpub' | 'privateKey'

type EncryptedData = {|
  +data: string,
  +nonce: string,
|}

declare type WalletEncryptedData = {|
  +mnemonic: ?EncryptedData,
  +privateKey: ?EncryptedData,
|}

declare type ScryptParams = {|
  +N: number,
  +r: number,
  +p: number,
|}

declare type PasswordOptions = {|
  scryptParams: ScryptParams,
  salt: string,
  passwordHint: ?string,
  encryptionType: string,
|}

declare type MnemonicOptions = {|
  network: Network,
  passphrase: string,
  derivationPath: string,
  paddedMnemonicLength: number,
|}

declare type PasswordOptionsUser = {|
  scryptParams?: ScryptParams,
  passwordHint?: string,
  encryptionType?: string,
|}

declare type MnemonicOptionsUser = {|
  network?: Network,
  passphrase?: string,
  derivationPath?: string,
  paddedMnemonicLength?: number,
|}

declare type Wallet = {|
  +passwordOptions: ?PasswordOptions,
  +mnemonicOptions: ?MnemonicOptions,
  +encrypted: WalletEncryptedData,
  +id: string,
  +name: string,
  +type: WalletType,
  +address: ?string,
  +bip32XPublicKey: ?string,
  +customType: WalletCustomType,
  +addressIndex: ?number,
  +isReadOnly: boolean,
|}

declare type WalletUpdatedData = {|
  +passwordOptions?: PasswordOptions,
  +mnemonicOptions?: MnemonicOptions,
  +encrypted?: WalletEncryptedData,
  +name?: string,
  +bip32XPublicKey?: ?string,
  +customType?: ?WalletCustomType,
  +addressIndex?: ?number,
  +isReadOnly?: ?boolean,
|}

declare type WalletNewData = {|
  +scryptParams?: ScryptParams,
  +data: string,
  +name?: string,
  +network?: Network,
  +passphrase?: string,
  +derivationPath?: string,
  +encryptionType?: string,
  +saltBytesCount?: number,
  +derivedKeyLength?: number,
  +paddedMnemonicLength?: number,
|}

declare type WalletData = {|
  +passwordOptions: PasswordOptions,
  +mnemonicOptions: MnemonicOptions,
  +id: string,
  +data: string,
  +name: string,
|}

declare type WalletDecryptedData = {|
  +id: string,
  +name: string,
  +address: string,
  +mnemonic: string,
  +privateKey: string,
  +type: WalletCustomType,
  +readOnly: 'yes' | 'no',
  +bip32XPublicKey: string,
|}

declare type Wallets = Array<Wallet>

declare type Keystore = {|
  +wallets: Wallets,
  +testPasswordData: EncryptedData,
  +passwordOptions: PasswordOptions,
|}

declare type PasswordResult = {|
  +score: number,
  +feedback: {|
    +warning: string,
    +suggestions: Array<string>,
  |},
|}
