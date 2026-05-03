import { createKeychainOptions } from '../keychainHelpers'
import * as Keychain from 'react-native-keychain'
import * as LocalAuthentication from 'expo-local-authentication'

jest.mock('react-native-keychain', () => ({
  ACCESSIBLE: {
    WHEN_UNLOCKED: 'WHEN_UNLOCKED',
    WHEN_UNLOCKED_THIS_DEVICE_ONLY: 'WHEN_UNLOCKED_THIS_DEVICE_ONLY',
  },
  ACCESS_CONTROL: {
    BIOMETRY_ANY_OR_DEVICE_PASSCODE: 'BIOMETRY_ANY_OR_DEVICE_PASSCODE',
    DEVICE_PASSCODE: 'DEVICE_PASSCODE',
  },
}))

jest.mock('expo-local-authentication', () => ({
  SecurityLevel: {
    NONE: 0,
    SECRET: 1,
    BIOMETRIC: 2,
    BIOMETRIC_WEAK: 2,
    BIOMETRIC_STRONG: 3,
  },
}))

const { SecurityLevel } = LocalAuthentication

describe('createKeychainOptions', () => {
  describe('access control selection by security level', () => {
    it('should use BIOMETRY_ANY_OR_DEVICE_PASSCODE when security level is BIOMETRIC_WEAK', () => {
      const options = createKeychainOptions(SecurityLevel.BIOMETRIC_WEAK, true, true)

      expect(options).toHaveProperty(
        'accessControl',
        Keychain.ACCESS_CONTROL.BIOMETRY_ANY_OR_DEVICE_PASSCODE
      )
    })

    it('should use BIOMETRY_ANY_OR_DEVICE_PASSCODE when security level is BIOMETRIC_STRONG', () => {
      const options = createKeychainOptions(SecurityLevel.BIOMETRIC_STRONG, true, true)

      expect(options).toHaveProperty(
        'accessControl',
        Keychain.ACCESS_CONTROL.BIOMETRY_ANY_OR_DEVICE_PASSCODE
      )
    })

    it('should use DEVICE_PASSCODE when security level is SECRET (PIN only)', () => {
      const options = createKeychainOptions(SecurityLevel.SECRET, true, true)

      expect(options).toHaveProperty('accessControl', Keychain.ACCESS_CONTROL.DEVICE_PASSCODE)
    })

    it('should not set accessControl when security level is NONE', () => {
      const options = createKeychainOptions(SecurityLevel.NONE, true, true)

      expect(options).not.toHaveProperty('accessControl')
    })
  })

  describe('requireAuth=false bypasses access control', () => {
    it('should not set accessControl when requireAuth is false even with BIOMETRIC_WEAK', () => {
      const options = createKeychainOptions(SecurityLevel.BIOMETRIC_WEAK, false, true)

      expect(options).not.toHaveProperty('accessControl')
    })

    it('should not set accessControl when requireAuth is false even with SECRET', () => {
      const options = createKeychainOptions(SecurityLevel.SECRET, false, true)

      expect(options).not.toHaveProperty('accessControl')
    })
  })

  describe('accessible flag based on syncable', () => {
    it('should use WHEN_UNLOCKED when syncable is true', () => {
      const options = createKeychainOptions(SecurityLevel.BIOMETRIC_WEAK, true, true)

      expect(options).toHaveProperty('accessible', Keychain.ACCESSIBLE.WHEN_UNLOCKED)
    })

    it('should use WHEN_UNLOCKED_THIS_DEVICE_ONLY when syncable is false', () => {
      const options = createKeychainOptions(SecurityLevel.BIOMETRIC_WEAK, true, false)

      expect(options).toHaveProperty(
        'accessible',
        Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY
      )
    })
  })

  describe('defaults', () => {
    it('should default requireAuth to true', () => {
      const options = createKeychainOptions(SecurityLevel.BIOMETRIC_WEAK)

      expect(options).toHaveProperty(
        'accessControl',
        Keychain.ACCESS_CONTROL.BIOMETRY_ANY_OR_DEVICE_PASSCODE
      )
    })

    it('should default syncable to true', () => {
      const options = createKeychainOptions(SecurityLevel.NONE)

      expect(options).toHaveProperty('accessible', Keychain.ACCESSIBLE.WHEN_UNLOCKED)
    })
  })
})
