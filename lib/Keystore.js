'use strict';

var _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _objectWithoutProperties(obj, keys) { var target = {}; for (var i in obj) { if (keys.indexOf(i) >= 0) continue; if (!Object.prototype.hasOwnProperty.call(obj, i)) continue; target[i] = obj[i]; } return target; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var uuidv4 = require('uuid/v4');
var bitcore = require('bitcore-lib');
var Mnemonic = require('bitcore-mnemonic');

var _require = require('lodash'),
    find = _require.find,
    findIndex = _require.findIndex;

var utils = require('./utils');
var encryption = require('./encryption');
var _testPassword = require('./password');

var _require2 = require('./mnemonic'),
    _generateMnemonic = _require2.generateMnemonic,
    _isMnemonicValid = _require2.isMnemonicValid,
    _isBip32XPublicKeyValid = _require2.isBip32XPublicKeyValid;

var ADDRESS_LENGTH = 40;
var PRIVATE_KEY_LENGTH = 64;
var ADDRESSES_PER_ITERATION_LIMIT = 5;

var Keystore = function () {
  function Keystore() {
    var props = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};

    _classCallCheck(this, Keystore);

    this.accounts = [];
    this.defaultDerivationPath = props.defaultDerivationPath || "m/44'/60'/0'/0";
    this.defaultEncryptionType = props.defaultEncryptionType || 'nacl.secretbox';
    this.paddedMnemonicLength = props.paddedMnemonicLength || 120;
    this.saltByteCount = props.saltByteCount || 32;
    this.scryptParams = props.scryptParams || { N: 2 ** 18, r: 8, p: 1 };
    this.derivedKeyLength = props.derivedKeyLength || 32;
    this.passwordConfig = props.passwordConfig || {};
    this.mnemonicType = 'mnemonic';
    this.addressType = 'address';
    this.checkPasswordData = null;
    this.salt = utils.generateSalt(this.saltByteCount);
    this.version = 1;
  }

  _createClass(Keystore, [{
    key: 'getAccounts',
    value: function getAccounts() {
      return this.accounts;
    }
  }, {
    key: 'getAccount',
    value: function getAccount(findProps) {
      if (!(findProps && findProps.id)) {
        throw new Error('Account ID not provided');
      }

      return this._getAccount(findProps);
    }
  }, {
    key: 'removeAccount',
    value: function removeAccount(accountId) {
      var accountIndex = this._getAccountIndex(accountId);

      if (accountIndex === -1) {
        return false;
      }

      this.accounts.splice(accountIndex, 1);

      return true;
    }
  }, {
    key: 'removeAccounts',
    value: function removeAccounts() {
      this.accounts = [];
    }
  }, {
    key: 'createAccount',
    value: function createAccount(props) {
      var type = props.type,
          isReadOnly = props.isReadOnly,
          password = props.password,
          accountName = props.accountName,
          otherProps = _objectWithoutProperties(props, ['type', 'isReadOnly', 'password', 'accountName']);

      this._checkAccountUniqueness({ accountName: accountName }, 'name');

      var extendedAccountInfo = this._getExtendedAccountInfo(accountName);
      var accountData = _extends({}, otherProps, extendedAccountInfo, { password: password });

      this._checkPassword(password);

      var createAccountHandler = void 0;

      if (type === this.mnemonicType) {
        createAccountHandler = isReadOnly ? this._createReadOnlyMnemonicAccount : this._createMnemonicAccount;
      } else if (type === this.addressType) {
        createAccountHandler = isReadOnly ? this._createReadOnlyAddressAccount : this._createAddressAccount;
      } else {
        throw new Error('Type of account not provided or incorrect');
      }

      createAccountHandler.call(this, accountData);

      return accountData.id;
    }
  }, {
    key: 'setAccountName',
    value: function setAccountName(accountId, accountName) {
      var account = this.getAccount({ id: accountId });

      this._checkAccountExist(account);
      this._checkAccountUniqueness({ accountName: accountName }, 'name');

      if (!(accountName && accountName.length)) {
        throw new Error('New account name should be not empty');
      }

      return this._setAccount(account, { accountName: accountName });
    }
  }, {
    key: 'getPrivateKey',
    value: function getPrivateKey(password, accountId) {
      var addressIndex = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 0;

      var account = this.getAccount({ id: accountId });

      this._checkAccountExist(account);
      this._checkReadOnly(account);
      this._checkPassword(password);

      var type = account.type,
          encrypted = account.encrypted;


      var privateKey = type === 'address' ? this._decryptData(encrypted.privateKey, password, true) : this._getPrivateKeyFromMnemonic(password, account, addressIndex);

      return utils.add0x(privateKey);
    }
  }, {
    key: 'setAddressIndex',
    value: function setAddressIndex(accountId) {
      var addressIndex = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 0;

      var account = this.getAccount({ id: accountId, type: this.mnemonicType });

      this._checkAccountExist(account);

      return this._setAccount(account, { addressIndex: addressIndex });
    }
  }, {
    key: 'setDerivationPath',
    value: function setDerivationPath(password, accountId, newDerivationPath) {
      var account = this.getAccount({ id: accountId, type: this.mnemonicType });

      this._checkAccountExist(account);
      this._checkReadOnly(account);
      this._checkPassword(password);

      if (!this.constructor.isDerivationPathValid(newDerivationPath)) {
        throw new Error('Invalid derivation path');
      }

      var encrypted = account.encrypted,
          derivationPath = account.derivationPath;


      if (newDerivationPath === derivationPath) {
        throw new Error('Can not set the same derivation path');
      }

      var xpub = this._getXPubFromMnemonic(password, encrypted.mnemonic, newDerivationPath);

      this._checkAccountUniqueness({ bip32XPublicKey: xpub }, 'xpub');

      return this._setAccount(account, {
        derivationPath: newDerivationPath,
        bip32XPublicKey: xpub
      });
    }
  }, {
    key: 'getAddressesFromMnemonic',
    value: function getAddressesFromMnemonic(accountId) {
      var iteration = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 0;
      var limit = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : ADDRESSES_PER_ITERATION_LIMIT;

      var account = this.getAccount({ id: accountId, type: this.mnemonicType });

      this._checkAccountExist(account);

      return this._generateAddresses(account.bip32XPublicKey, iteration, limit);
    }
  }, {
    key: 'getMnemonic',
    value: function getMnemonic(password, accountId) {
      var account = this.getAccount({ id: accountId, type: this.mnemonicType });

      this._checkAccountExist(account);
      this._checkReadOnly(account);
      this._checkPassword(password);

      var paddedMnemonic = this._decryptData(account.encrypted.mnemonic, password);

      return paddedMnemonic.trim();
    }
  }, {
    key: 'serialize',
    value: function serialize() {
      return JSON.stringify(this._getBackupData());
    }
  }, {
    key: 'deserialize',
    value: function deserialize(backupData) {
      var data = void 0;

      try {
        data = JSON.parse(backupData);
      } catch (err) {
        throw new Error('Failed to parse backup data');
      }

      this._restoreBackupData(data);

      return data;
    }
  }, {
    key: 'getDecryptedAccounts',
    value: function getDecryptedAccounts(password) {
      var _this = this;

      this._checkPassword(password);

      return this.accounts.map(function (account) {
        var isReadOnly = account.isReadOnly,
            type = account.type,
            accountName = account.accountName,
            address = account.address,
            encrypted = account.encrypted;
        var privateKey = encrypted.privateKey,
            mnemonic = encrypted.mnemonic;


        var decryptedPrivateKey = privateKey ? _this._decryptData(privateKey, password) : null;
        var decryptedMnemonic = mnemonic ? _this._decryptData(mnemonic, password) : null;

        return {
          accountName: accountName,
          type: type,
          readOnly: isReadOnly ? 'yes' : 'no',
          address: address || 'n/a',
          privateKey: decryptedPrivateKey || 'n/a',
          mnemonic: decryptedMnemonic ? decryptedMnemonic.trim() : 'n/a'
        };
      });
    }
  }, {
    key: 'setPassword',
    value: function setPassword(password, newPassword) {
      this._checkPassword(password);
      this._setPasswordDataToCheck(newPassword);
      this._reEncryptData(password, newPassword);
    }
  }, {
    key: '_createMnemonicAccount',
    value: function _createMnemonicAccount(props) {
      var id = props.id,
          password = props.password,
          accountName = props.accountName;

      var mnemonic = props.mnemonic.toLowerCase();
      var derivationPath = props.derivationPath || this.defaultDerivationPath;

      if (!_isMnemonicValid(mnemonic)) {
        throw new Error('Invalid mnemonic');
      } else if (!this.constructor.isDerivationPathValid(derivationPath)) {
        throw new Error('Invalid derivation path');
      }

      var paddedMnemonic = utils.leftPadString(mnemonic, ' ', this.paddedMnemonicLength);
      var encryptedMnemonic = this._encryptData(paddedMnemonic, password);
      var bip32XPublicKey = this._getXPubFromMnemonic(password, encryptedMnemonic, derivationPath);

      this._checkAccountUniqueness({ bip32XPublicKey: bip32XPublicKey }, 'xpub');

      this.accounts.push({
        type: this.mnemonicType,
        id: id,
        accountName: accountName,
        derivationPath: derivationPath,
        bip32XPublicKey: bip32XPublicKey,
        isReadOnly: false,
        addressIndex: 0,
        encrypted: {
          mnemonic: encryptedMnemonic
        }
      });
    }
  }, {
    key: '_createReadOnlyMnemonicAccount',
    value: function _createReadOnlyMnemonicAccount(props) {
      var id = props.id,
          bip32XPublicKey = props.bip32XPublicKey,
          accountName = props.accountName;


      if (!_isBip32XPublicKeyValid(bip32XPublicKey)) {
        throw new Error('Invalid bip32XPublicKey');
      }

      this._checkAccountUniqueness({ bip32XPublicKey: bip32XPublicKey }, 'xpub');

      this.accounts.push({
        type: this.mnemonicType,
        id: id,
        accountName: accountName,
        bip32XPublicKey: bip32XPublicKey,
        isReadOnly: true,
        addressIndex: 0,
        encrypted: {}
      });
    }
  }, {
    key: '_createAddressAccount',
    value: function _createAddressAccount(props) {
      var id = props.id,
          password = props.password,
          accountName = props.accountName;

      var privateKey = props.privateKey.toLowerCase();

      if (!utils.isHexStringValid(privateKey, PRIVATE_KEY_LENGTH)) {
        throw new Error('Private Key is invalid');
      }

      var address = utils.getAddressFromPrivateKey(privateKey);

      this._checkAccountUniqueness({ address: address }, 'address');

      this.accounts.push({
        type: this.addressType,
        id: id,
        address: address,
        accountName: accountName,
        isReadOnly: false,
        encrypted: {
          privateKey: this._encryptData(privateKey, password, true)
        }
      });
    }
  }, {
    key: '_createReadOnlyAddressAccount',
    value: function _createReadOnlyAddressAccount(props) {
      var id = props.id,
          accountName = props.accountName;

      var address = props.address.toLowerCase();

      if (!utils.isHexStringValid(address, ADDRESS_LENGTH)) {
        throw new Error('Address is invalid');
      }

      this._checkAccountUniqueness({ address: address }, 'address');

      this.accounts.push({
        type: this.addressType,
        id: id,
        address: address,
        accountName: accountName,
        isReadOnly: true,
        encrypted: {}
      });
    }
  }, {
    key: '_getExtendedAccountInfo',
    value: function _getExtendedAccountInfo(accountName) {
      var id = uuidv4();

      return { id: uuidv4(), accountName: accountName || id };
    }
  }, {
    key: '_deriveKeyFromPassword',
    value: function _deriveKeyFromPassword(password) {
      var scryptParams = this.scryptParams,
          derivedKeyLength = this.derivedKeyLength,
          salt = this.salt;


      return utils.deriveKeyFromPassword(password, scryptParams, derivedKeyLength, salt);
    }
  }, {
    key: '_encryptData',
    value: function _encryptData(dataToEncrypt, password) {
      var isPrivateKey = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : false;

      return encryption.encryptData({
        isPrivateKey: isPrivateKey,
        data: dataToEncrypt,
        encryptionType: this.defaultEncryptionType,
        derivedKey: this._deriveKeyFromPassword(password)
      });
    }
  }, {
    key: '_decryptData',
    value: function _decryptData(dataToDecrypt, password) {
      var isPrivateKey = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : false;

      return encryption.decryptData({
        isPrivateKey: isPrivateKey,
        data: dataToDecrypt,
        derivedKey: this._deriveKeyFromPassword(password)
      });
    }
  }, {
    key: '_getPrivateKeyFromMnemonic',
    value: function _getPrivateKeyFromMnemonic(password, account, addressIndex) {
      var encrypted = account.encrypted,
          derivationPath = account.derivationPath;

      var hdRoot = this._getPrivateHdRoot(password, encrypted.mnemonic, derivationPath);
      var generatedKey = this._generateKey(hdRoot, addressIndex);

      return generatedKey.privateKey.toString();
    }
  }, {
    key: '_generateAddresses',
    value: function _generateAddresses(bip32XPublicKey, iteration, limit) {
      var keyIndexStart = iteration * limit;
      var keyIndexEnd = keyIndexStart + limit;

      var addresses = [];

      var hdRoot = this._getPublicHdRoot(bip32XPublicKey);

      for (var index = keyIndexStart; index < keyIndexEnd; index += 1) {
        var generatedKey = this._generateKey(hdRoot, index);
        var publicKey = generatedKey.publicKey.toString();
        var address = utils.getAddressFromPublicKey(publicKey);

        addresses.push(address);
      }

      return addresses;
    }
  }, {
    key: '_generateKey',
    value: function _generateKey(hdRoot, keyIndexToDerive) {
      return hdRoot.derive(keyIndexToDerive);
    }
  }, {
    key: '_getHdPath',
    value: function _getHdPath(mnemonic, derivationPath) {
      var hdRoot = new Mnemonic(mnemonic.trim()).toHDPrivateKey().xprivkey;
      var hdRootKey = new bitcore.HDPrivateKey(hdRoot);

      return hdRootKey.derive(derivationPath).xprivkey;
    }
  }, {
    key: '_getPublicHdRoot',
    value: function _getPublicHdRoot(bip32XPublicKey) {
      return new bitcore.HDPublicKey(bip32XPublicKey);
    }
  }, {
    key: '_getPrivateHdRoot',
    value: function _getPrivateHdRoot(password, encryptedMnemonic, derivationPath) {
      var mnemonic = this._decryptData(encryptedMnemonic, password);
      var hdPath = this._getHdPath(mnemonic, derivationPath);

      return new bitcore.HDPrivateKey(hdPath);
    }
  }, {
    key: '_getXPubFromMnemonic',
    value: function _getXPubFromMnemonic(password, encryptedMnemonic, derivationPath) {
      var hdRoot = this._getPrivateHdRoot(password, encryptedMnemonic, derivationPath);

      return hdRoot.hdPublicKey.toString();
    }
  }, {
    key: '_setAccount',
    value: function _setAccount(account, props) {
      var accountIndex = this._getAccountIndex(account.id);

      if (accountIndex === -1) {
        throw new Error('Account not found');
      }

      var newAccount = _extends({}, account, props);

      this.accounts.splice(accountIndex, 1, newAccount);

      return newAccount;
    }
  }, {
    key: '_getAccount',
    value: function _getAccount(findProps) {
      return find(this.accounts, findProps);
    }
  }, {
    key: '_getAccountIndex',
    value: function _getAccountIndex(accountId) {
      return findIndex(this.accounts, { id: accountId });
    }
  }, {
    key: '_getBackupData',
    value: function _getBackupData() {
      var accounts = this.accounts,
          defaultDerivationPath = this.defaultDerivationPath,
          defaultEncryptionType = this.defaultEncryptionType,
          scryptParams = this.scryptParams,
          derivedKeyLength = this.derivedKeyLength,
          checkPasswordData = this.checkPasswordData,
          salt = this.salt,
          version = this.version;


      return {
        accounts: accounts,
        defaultDerivationPath: defaultDerivationPath,
        defaultEncryptionType: defaultEncryptionType,
        scryptParams: scryptParams,
        derivedKeyLength: derivedKeyLength,
        checkPasswordData: checkPasswordData,
        salt: salt,
        version: version
      };
    }
  }, {
    key: '_restoreBackupData',
    value: function _restoreBackupData(backupData) {
      if (backupData.version === 1) {
        var accounts = backupData.accounts,
            defaultDerivationPath = backupData.defaultDerivationPath,
            defaultEncryptionType = backupData.defaultEncryptionType,
            scryptParams = backupData.scryptParams,
            derivedKeyLength = backupData.derivedKeyLength,
            checkPasswordData = backupData.checkPasswordData,
            salt = backupData.salt;


        this.accounts = accounts || [];
        this.defaultDerivationPath = defaultDerivationPath || this.defaultDerivationPath;
        this.defaultEncryptionType = defaultEncryptionType || this.defaultEncryptionType;
        this.scryptParams = scryptParams || this.scryptParams;
        this.derivedKeyLength = derivedKeyLength || this.derivedKeyLength;
        this.checkPasswordData = checkPasswordData || this.checkPasswordData;
        this.salt = salt || this.salt;
        this.version = 1;
      }
    }
  }, {
    key: '_checkAccountExist',
    value: function _checkAccountExist(account) {
      if (!account) {
        throw new Error('Account not found');
      }
    }
  }, {
    key: '_checkReadOnly',
    value: function _checkReadOnly(account) {
      if (account.isReadOnly) {
        throw new Error('Account is read only');
      }
    }
  }, {
    key: '_checkPassword',
    value: function _checkPassword(password) {
      if (!this.checkPasswordData) {
        this._setPasswordDataToCheck(password);

        return;
      }

      var errMessage = 'Password is incorrect';

      try {
        var decryptedData = this._decryptData(this.checkPasswordData, password);

        if (!(decryptedData && decryptedData.length)) {
          throw new Error(errMessage);
        }
      } catch (e) {
        throw new Error(errMessage);
      }
    }
  }, {
    key: '_checkAccountUniqueness',
    value: function _checkAccountUniqueness(uniqueProperty, propertyName) {
      var isAccountExist = !!this._getAccount(uniqueProperty);

      if (isAccountExist) {
        throw new Error('Account with this ' + propertyName + ' already exists');
      }
    }
  }, {
    key: '_setPasswordDataToCheck',
    value: function _setPasswordDataToCheck(password) {
      var testPasswordResult = _testPassword(password, this.passwordConfig);

      if (testPasswordResult.failedTests.length) {
        throw new Error('Password is too weak');
      }

      var checkPasswordData = utils.generateSalt(this.saltByteCount);

      this.checkPasswordData = this._encryptData(checkPasswordData, password);
    }
  }, {
    key: '_reEncryptData',
    value: function _reEncryptData(password, newPassword) {
      var _this2 = this;

      this.accounts.forEach(function (account) {
        var isReadOnly = account.isReadOnly,
            encrypted = account.encrypted;


        if (isReadOnly) {
          return;
        }

        var newEncrypted = {};

        Object.keys(encrypted).forEach(function (key) {
          var encryptedItem = encrypted[key];
          var isPrivateKey = key === 'privateKey';

          if (encryptedItem) {
            var decryptedItem = _this2._decryptData(encryptedItem, password, isPrivateKey);

            newEncrypted[key] = _this2._encryptData(decryptedItem, newPassword);
          } else {
            newEncrypted[key] = encryptedItem;
          }
        });

        _this2._setAccount(account, { encrypted: newEncrypted });
      });
    }
  }], [{
    key: 'generateMnemonic',
    value: function generateMnemonic(entropy) {
      var randomBufferLength = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 32;

      return _generateMnemonic(entropy, randomBufferLength);
    }
  }, {
    key: 'isMnemonicValid',
    value: function isMnemonicValid(mnemonic) {
      return _isMnemonicValid(mnemonic);
    }
  }, {
    key: 'isBip32XPublicKeyValid',
    value: function isBip32XPublicKeyValid(bip32XPublicKey) {
      return _isBip32XPublicKeyValid(bip32XPublicKey);
    }
  }, {
    key: 'isHexStringValid',
    value: function isHexStringValid(hash, hashLength) {
      return utils.isHexStringValid(hash, hashLength);
    }
  }, {
    key: 'isDerivationPathValid',
    value: function isDerivationPathValid(derivationPath) {
      return bitcore.HDPrivateKey.isValidPath(derivationPath);
    }
  }, {
    key: 'testPassword',
    value: function testPassword(password, passwordConfig) {
      return _testPassword(password, passwordConfig);
    }
  }]);

  return Keystore;
}();

module.exports = Keystore;