'use strict';

var _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

function testPasswordMinLength(password, _ref) {
  var minLength = _ref.minLength;

  if (password.length < minLength) {
    return 'The password must be at least ' + minLength + ' characters long';
  }

  return null;
}

function testPasswordMaxLength(password, _ref2) {
  var maxLength = _ref2.maxLength;

  if (password.length > maxLength) {
    return 'The password must be fewer than ' + maxLength + ' characters long';
  }

  return null;
}

function testRepeatingCharacters(password) {
  if (/(.)\1{2,}/.test(password)) {
    return 'The password may not contain three or more repeating symbols';
  }

  return null;
}

function testLowercaseLetter(password) {
  if (!/[a-z]/.test(password)) {
    return 'The password must contain at least one lowercase letter';
  }

  return null;
}

function testUppercaseLetter(password) {
  if (!/[A-Z]/.test(password)) {
    return 'The password must contain at least one uppercase letter';
  }

  return null;
}

function testNumber(password) {
  if (!/\d/.test(password)) {
    return 'The password must contain at least one number';
  }

  return null;
}

function testSpecialCharacter(password) {
  if (!/[^A-Za-z0-9]/.test(password)) {
    return 'The password must contain at least one special character';
  }

  return null;
}

var tests = {
  minlen: testPasswordMinLength,
  maxlen: testPasswordMaxLength,
  repeat: testRepeatingCharacters,
  lowerc: testLowercaseLetter,
  upperc: testUppercaseLetter,
  number: testNumber,
  specch: testSpecialCharacter
};

var defaultConfig = { maxLength: 128, minLength: 10 };

function testPassword(password) {
  var config = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};

  var mergedConfig = _extends({}, defaultConfig, config);

  var result = {
    errors: [],
    failedTests: [],
    passedTests: []
  };

  Object.keys(tests).forEach(function (test) {
    var testResult = tests[test](password, mergedConfig);

    if (!testResult) {
      result.passedTests.push(test);
    } else {
      result.failedTests.push(test);
      result.errors.push(testResult);
    }
  });

  return result;
}

module.exports = testPassword;