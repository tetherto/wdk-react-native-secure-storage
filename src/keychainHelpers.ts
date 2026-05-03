import * as Keychain from 'react-native-keychain'
import * as LocalAuthentication from 'expo-local-authentication'

/**
 * Keychain options for setGenericPassword
 */
export type KeychainOptions = Parameters<typeof Keychain.setGenericPassword>[2]

/**
 * Create keychain options with conditional access control
 * 
 * On Android, BIOMETRY_ANY_OR_DEVICE_PASSCODE requires at least one biometric
 * (e.g. fingerprint) to be enrolled for BiometricPrompt to render. If the device
 * only has a PIN/pattern/password, BiometricPrompt never appears and the keychain
 * read silently fails. We use the security level to pick the right access control:
 * - BIOMETRIC_WEAK/STRONG -> BIOMETRY_ANY_OR_DEVICE_PASSCODE (prompt with PIN fallback)
 * - SECRET                -> DEVICE_PASSCODE (PIN/pattern/password prompt directly)
 * - NONE                  -> no access control
 * 
 * @param securityLevel - The device security level from expo-local-authentication
 * @param requireAuth - Whether authentication should be required for this operation
 * @param syncable - Whether the value should sync across devices (default: true)
 * @returns Keychain options object with appropriate access control settings
 */
export function createKeychainOptions(
  securityLevel: LocalAuthentication.SecurityLevel,
  requireAuth: boolean = true,
  syncable: boolean = true
): KeychainOptions {
  const options: KeychainOptions = {
    accessible: syncable 
      ? Keychain.ACCESSIBLE.WHEN_UNLOCKED 
      : Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  }
  
  const isBiometricSecurityLevel =
    securityLevel === LocalAuthentication.SecurityLevel.BIOMETRIC_WEAK ||
    securityLevel === LocalAuthentication.SecurityLevel.BIOMETRIC_STRONG
  
  if (requireAuth && securityLevel !== LocalAuthentication.SecurityLevel.NONE) {
    options.accessControl = isBiometricSecurityLevel
      ? Keychain.ACCESS_CONTROL.BIOMETRY_ANY_OR_DEVICE_PASSCODE
      : Keychain.ACCESS_CONTROL.DEVICE_PASSCODE
  }
  
  return options
}


