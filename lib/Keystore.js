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
    isBip32XPublicKeyValid = _require2.isBip32XPublicKeyValid;

var ADDRESS_LENGTH = 40;
var PRIVATE_KEY_LENGTH = 64;

var Keystore = function () {
  function Keystore() {
    var props = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};

    _classCallCheck(this, Keystore);

    this.accounts = props.accounts || [];
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

      return find(this.accounts, findProps);
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
    value: function setAccountName(accountId, newName) {
      var account = this.getAccount({ id: accountId });

      this._checkAccountExist(account);

      if (!(newName && newName.length)) {
        throw new Error('New account name should be not empty');
      }

      return this._setAccount(account, { accountName: newName });
    }
  }, {
    key: 'getPrivateKey',
    value: function getPrivateKey(password, accountId) {
      var account = this.getAccount({ id: accountId });

      this._checkAccountExist(account);
      this._checkReadOnly(account);
      this._checkPassword(password);

      var encrypted = account.encrypted;

      var dataToDecrypt = encrypted.privateKey;

      if (!dataToDecrypt) {
        throw new Error('Address is not setted yet');
      }

      var decryptedData = this._decryptData(dataToDecrypt, password, true);

      return utils.add0x(decryptedData);
    }
  }, {
    key: 'setAddress',
    value: function setAddress(password, accountId) {
      var addressIndex = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 0;

      var account = this.getAccount({ id: accountId, type: this.mnemonicType });

      this._checkAccountExist(account);

      if (!account.isReadOnly) {
        this._checkPassword(password);
      }

      var encrypted = account.encrypted,
          isReadOnly = account.isReadOnly;

      var hdRoot = this._getHdRoot(password, account);
      var generatedKey = this._generateKey(hdRoot, addressIndex);

      if (isReadOnly) {
        return this._setAccount(account, {
          address: utils.getAddressFromPublicKey(generatedKey.publicKey.toString())
        });
      }

      var privateKey = generatedKey.privateKey.toString();

      return this._setAccount(account, {
        address: utils.getAddressFromPrivateKey(privateKey),
        encrypted: _extends({}, encrypted, {
          privateKey: this._encryptData(privateKey, password, true)
        })
      });
    }
  }, {
    key: 'setDerivationPath',
    value: function setDerivationPath(password, accountId, newDerivationPath) {
      var account = this.getAccount({ id: accountId, type: this.mnemonicType });

      this._checkAccountExist(account);
      this._checkReadOnly(account);
      this._checkPassword(password);

      if (!(newDerivationPath && newDerivationPath.length)) {
        throw new Error('New derivation path should be not empty');
      }

      var encrypted = account.encrypted;

      var mnemonic = this._decryptData(encrypted.mnemonic, password);
      var hdPath = this._getHdPath(mnemonic, newDerivationPath);

      return this._setAccount(account, {
        derivationPath: newDerivationPath,
        encrypted: _extends({}, encrypted, {
          hdPath: this._encryptData(hdPath, password)
        })
      });
    }
  }, {
    key: 'getAddressesFromMnemonic',
    value: function getAddressesFromMnemonic(password, accountId, iteration, limit) {
      var account = this.getAccount({ id: accountId, type: this.mnemonicType });

      this._checkAccountExist(account);

      if (!account.isReadOnly) {
        this._checkPassword(password);
      }

      return this._generateAddresses(password, account, iteration, limit);
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
          mnemonic: decryptedMnemonic || 'n/a'
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
          mnemonic = props.mnemonic,
          accountName = props.accountName;

      var derivationPath = props.derivationPath || this.defaultDerivationPath;

      if (!_isMnemonicValid(mnemonic)) {
        throw new Error('Invalid mnemonic');
      }

      var hdPath = this._getHdPath(mnemonic, derivationPath);
      var paddedMnemonic = utils.leftPadString(mnemonic, ' ', this.paddedMnemonicLength);

      this.accounts.push({
        type: this.mnemonicType,
        id: id,
        accountName: accountName,
        derivationPath: derivationPath,
        isReadOnly: false,
        address: null,
        encrypted: {
          privateKey: null,
          mnemonic: this._encryptData(paddedMnemonic, password),
          hdPath: this._encryptData(hdPath, password)
        }
      });
    }
  }, {
    key: '_createReadOnlyMnemonicAccount',
    value: function _createReadOnlyMnemonicAccount(props) {
      var id = props.id,
          bip32XPublicKey = props.bip32XPublicKey,
          accountName = props.accountName;


      if (!isBip32XPublicKeyValid(bip32XPublicKey)) {
        throw new Error('Invalid bip32XPublicKey');
      }

      this.accounts.push({
        type: this.mnemonicType,
        id: id,
        accountName: accountName,
        bip32XPublicKey: bip32XPublicKey,
        isReadOnly: true,
        address: null,
        encrypted: {}
      });
    }
  }, {
    key: '_createAddressAccount',
    value: function _createAddressAccount(props) {
      var id = props.id,
          password = props.password,
          privateKey = props.privateKey,
          accountName = props.accountName;


      if (!utils.isHexStringValid(privateKey, PRIVATE_KEY_LENGTH)) {
        throw new Error('Private Key is invalid');
      }

      var address = utils.getAddressFromPrivateKey(privateKey);

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
          address = props.address,
          accountName = props.accountName;


      if (!utils.isHexStringValid(address, ADDRESS_LENGTH)) {
        throw new Error('Address is invalid');
      }

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
      return {
        id: uuidv4(),
        accountName: accountName || 'Account ' + (this.accounts.length + 1)
      };
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
    key: '_generateAddresses',
    value: function _generateAddresses(password, account) {
      var iteration = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 0;
      var limit = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : 5;

      var keyIndexStart = iteration * limit;
      var keyIndexEnd = keyIndexStart + limit;

      var addresses = [];

      var hdRoot = this._getHdRoot(password, account);

      for (var index = keyIndexStart; index < keyIndexEnd; index += 1) {
        var key = this._generateKey(hdRoot, index);

        var address = account.isReadOnly ? utils.getAddressFromPublicKey(key.publicKey.toString()) : utils.getAddressFromPrivateKey(key.privateKey.toString());

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
    key: '_getHdRoot',
    value: function _getHdRoot(password, account) {
      var bip32XPublicKey = account.bip32XPublicKey,
          encrypted = account.encrypted,
          isReadOnly = account.isReadOnly;


      return isReadOnly ? new bitcore.HDPublicKey(bip32XPublicKey) : new bitcore.HDPrivateKey(this._decryptData(encrypted.hdPath, password));
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
    key: 'isMnemonicValid',
    value: function isMnemonicValid(mnemonic) {
      return _isMnemonicValid(mnemonic);
    }
  }, {
    key: 'generateMnemonic',
    value: function generateMnemonic(entropy) {
      var randomBufferLength = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 32;

      return _generateMnemonic(entropy, randomBufferLength);
    }
  }, {
    key: 'isHexStringValid',
    value: function isHexStringValid(hash, hashLength) {
      return utils.isHexStringValid(hash, hashLength);
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