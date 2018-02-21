const R = require('ramda')

const migrateTo070 = (backupData) => {
  if (backupData.version >= '0.7.0') {
    return backupData
  }

  const { wallets, accounts, salt } = backupData

  const prepareWallet = (wallet) => {
    const { accountName, type, isReadOnly } = wallet

    const mnemonicType = isReadOnly ? 'bip32Xpub' : 'mnemonic'
    const addressType = isReadOnly ? 'address' : 'privateKey'
    const customType = (type === 'mnemonic') ? mnemonicType : addressType

    return R.compose(
      R.assoc('name', accountName),
      R.assoc('customType', customType),
      R.assoc('salt', isReadOnly ? null : salt)
    )(wallet)
  }

  const newWallets = R.map(prepareWallet)(accounts)

  return R.compose(
    R.assoc('version', '0.7.0'),
    R.assoc('wallets', R.concat(wallets || [])(newWallets))
  )(backupData)
}

const migrate = (backupData) => {
  return migrateTo070(backupData)
}

module.exports = migrate
