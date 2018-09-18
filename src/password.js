// @flow

import zxcvbn from 'zxcvbn'

export function testPassword(password: string): PasswordResult {
  const { score, feedback }: PasswordResult = zxcvbn(password)

  return { score, feedback }
}
