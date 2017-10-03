function testPasswordMinLength(password, { minLength }) {
  if (password.length < minLength) {
    return `The password must be at least ${minLength} characters long.`
  }

  return null
}

function testPasswordMaxLength(password, { maxLength }) {
  if (password.length > maxLength) {
    return `The password must be fewer than ${maxLength} characters long.`
  }

  return null
}

function testRepeatingCharacters(password) {
  if (/(.)\1{2,}/.test(password)) {
    return 'The password may not contain sequences of three or more repeated characters.'
  }

  return null
}

function testLowercaseLetter(password) {
  if (!/[a-z]/.test(password)) {
    return 'The password must contain at least one lowercase letter.'
  }

  return null
}

function testUppercaseLetter(password) {
  if (!/[A-Z]/.test(password)) {
    return 'The password must contain at least one uppercase letter.'
  }

  return null
}

function testNumber(password) {
  if (!/\d/.test(password)) {
    return 'The password must contain at least one number.'
  }

  return null
}

function testSpecialCharacter(password) {
  if (!/[^\s\d]/.test(password)) {
    return 'The password must contain at least one special character.'
  }

  return null
}

const tests = [
  testPasswordMinLength,
  testPasswordMaxLength,
  testRepeatingCharacters,
  testLowercaseLetter,
  testUppercaseLetter,
  testNumber,
  testSpecialCharacter,
]

const defaultConfig = { maxLength: 128, minLength: 10 }

function testPassword(password, config = {}) {
  const mergedConfig = { ...defaultConfig, ...config }

  const result = {
    errors: [],
    failedTests: 0,
    passedTests: 0,
  }

  tests.forEach((test) => {
    const testResult = test(password, mergedConfig)

    if (!testResult) {
      result.passedTests += 1
    } else {
      result.failedTests += 1
      result.errors.push(testResult)
    }
  })

  return result
}

module.exports = testPassword
