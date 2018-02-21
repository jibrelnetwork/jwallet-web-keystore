const R = require('ramda')

const migrateTo070 = (backupData) => {
  if (backupData.version >= '0.7.0') {
    return backupData
  }

  const { wallets, accounts, salt } = backupData

  const addSaltAndCustomTypeForWallets = (wallet) => {
    const { type, isReadOnly } = wallet

    const mnemonicType = isReadOnly ? 'bip32Xpub' : 'mnemonic'
    const addressType = isReadOnly ? 'address' : 'privateKey'
    const customType = (type === 'mnemonic') ? mnemonicType : addressType

    return R.compose(
      R.assoc('salt', salt),
      R.assoc('customType', customType)
    )(wallet)
  }

  const newWallets = R.map(addSaltAndCustomTypeForWallets)(accounts)

  return R.compose(
    R.assoc('version', '0.7.0'),
    R.assoc('wallets', R.concat(wallets || [])(newWallets))
  )(backupData)
}

const migrate = (backupData) => {
  return migrateTo070(backupData)
}

module.exports = migrate
