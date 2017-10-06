function testPasswordMinLength(password, { minLength }) {
  if (password.length < minLength) {
    return `The password must be at least ${minLength} characters long`
  }

  return null
}

function testPasswordMaxLength(password, { maxLength }) {
  if (password.length > maxLength) {
    return `The password must be fewer than ${maxLength} characters long`
  }

  return null
}

function testRepeatingCharacters(password) {
  if (/(.)\1{2,}/.test(password)) {
    return 'The password may not contain three or more repeating symbols'
  }

  return null
}

function testLowercaseLetter(password) {
  if (!/[a-z]/.test(password)) {
    return 'The password must contain at least one lowercase letter'
  }

  return null
}

function testUppercaseLetter(password) {
  if (!/[A-Z]/.test(password)) {
    return 'The password must contain at least one uppercase letter'
  }

  return null
}

function testNumber(password) {
  if (!/\d/.test(password)) {
    return 'The password must contain at least one number'
  }

  return null
}

function testSpecialCharacter(password) {
  if (!/[^A-Za-z0-9]/.test(password)) {
    return 'The password must contain at least one special character'
  }

  return null
}

const tests = {
  minlen: testPasswordMinLength,
  maxlen: testPasswordMaxLength,
  repeat: testRepeatingCharacters,
  lowerc: testLowercaseLetter,
  upperc: testUppercaseLetter,
  number: testNumber,
  specch: testSpecialCharacter,
}

const defaultConfig = { maxLength: 128, minLength: 10 }

function testPassword(password, config = {}) {
  const mergedConfig = { ...defaultConfig, ...config }

  const result = {
    errors: [],
    failedTests: [],
    passedTests: [],
  }

  Object.keys(tests).forEach((test) => {
    const testResult = tests[test](password, mergedConfig)

    if (!testResult) {
      result.passedTests.push(test)
    } else {
      result.failedTests.push(test)
      result.errors.push(testResult)
    }
  })

  return result
}

module.exports = testPassword
