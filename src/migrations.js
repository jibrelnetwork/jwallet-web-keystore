const R = require('ramda')

const migrateTo070 = (backupData) => {
  if (backupData.version >= '0.7.0') {
    return backupData
  }

  const { wallets, accounts, salt } = backupData

  const addSaltForWallets = wallet => R.assoc('salt', salt)(wallet)
  const newWallets = R.map(addSaltForWallets)(accounts)

  return R.compose(
    R.assoc('version', '0.7.0'),
    R.assoc('wallets', R.concat(wallets || [])(newWallets))
  )(backupData)
}

const migrate = (backupData) => {
  return migrateTo070(backupData)
}

module.exports = migrate
