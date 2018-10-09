declare type Address = string
declare type Addresses = Array<Address>

declare type Network = string | number

type EncryptedData = {|
  +data: string,
  +nonce: string,
|}

declare type ScryptParams = {|
  +N: number,
  +r: number,
  +p: number,
|}

declare type PasswordOptions = {|
  +scryptParams: ScryptParams,
  +salt: string,
  +passwordHint: string,
  +encryptionType: string,
  +saltBytesCount: number,
  +derivedKeyLength: number,
|}

declare type MnemonicOptions = {|
  +network: Network,
  +passphrase: string,
  +derivationPath: string,
  +paddedMnemonicLength: number,
|}

declare type PasswordOptionsUser = {|
  +scryptParams?: ScryptParams,
  +salt?: string,
  +passwordHint?: string,
  +encryptionType?: string,
  +saltBytesCount?: number,
  +derivedKeyLength?: number,
|}

declare type MnemonicOptionsUser = {|
  +network?: Network,
  +passphrase?: string,
  +derivationPath?: string,
  +paddedMnemonicLength?: number,
|}

declare type PasswordResult = {|
  +score: number,
  +feedback: {|
    +warning: string,
    +suggestions: Array<string>,
  |},
|}
