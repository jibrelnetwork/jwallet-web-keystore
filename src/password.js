// @flow

type PasswordTestKey = 'minlen' | 'maxlen' | 'repeat' | 'lowerc' | 'upperc' | 'number' | 'specch'
type PasswordTest = (string, PasswordConfig) => ?string
type PasswordTests = { +[PasswordTestKey]: PasswordTest }

const DEFAULT_CONFIG: PasswordConfig = {
  minLength: 10,
  maxLength: 128,
}

function testPasswordMinLength(password: string, { minLength }: PasswordConfig): ?string {
  if (password.length < minLength) {
    return `The password must be at least ${minLength} characters long`
  }

  return null
}

function testPasswordMaxLength(password: string, { maxLength }: PasswordConfig): ?string {
  if (password.length > maxLength) {
    return `The password must be fewer than ${maxLength} characters long`
  }

  return null
}

function testRepeatingCharacters(password: string): ?string {
  if (/(.)\1{2,}/.test(password)) {
    return 'The password may not contain three or more repeating symbols'
  }

  return null
}

function testLowercaseLetter(password: string): ?string {
  if (!/[a-z]/.test(password)) {
    return 'The password must contain at least one lowercase letter'
  }

  return null
}

function testUppercaseLetter(password: string): ?string {
  if (!/[A-Z]/.test(password)) {
    return 'The password must contain at least one uppercase letter'
  }

  return null
}

function testNumber(password: string): ?string {
  if (!/\d/.test(password)) {
    return 'The password must contain at least one number'
  }

  return null
}

function testSpecialCharacter(password: string): ?string {
  if (!/[^A-Za-z0-9]/.test(password)) {
    return 'The password must contain at least one special character'
  }

  return null
}

const TESTS: PasswordTests = {
  minlen: testPasswordMinLength,
  maxlen: testPasswordMaxLength,
  repeat: testRepeatingCharacters,
  lowerc: testLowercaseLetter,
  upperc: testUppercaseLetter,
  number: testNumber,
  specch: testSpecialCharacter,
}

export function testPassword(
  password: string,
  config?: {
    +minLength?: number,
    +maxLength?: number,
  },
): PasswordResult {
  return Object
    .keys(TESTS)
    .reduce((result: PasswordResult, test: PasswordTestKey): PasswordResult => {
      const mergedConfig: PasswordConfig = config
        ? Object.assign({}, DEFAULT_CONFIG, {
          minLength: config.minLength || DEFAULT_CONFIG.minLength,
          maxLength: config.maxLength || DEFAULT_CONFIG.maxLength,
        })
        : DEFAULT_CONFIG

      const testResult: ?string = TESTS[test](password, mergedConfig)

      if (!testResult) {
        return Object.assign({}, result, {
          passedTests: result.passedTests.concat(test),
        })
      }

      return Object.assign({}, result, {
        errors: result.errors.concat(testResult),
        failedTests: result.failedTests.concat(test),
      })
    }, {
      errors: [],
      failedTests: [],
      passedTests: [],
    })
}
