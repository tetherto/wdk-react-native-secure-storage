/**
 * Base error class for all secure storage errors
 */
export class SecureStorageError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly cause?: Error
  ) {
    super(message)
    this.name = 'SecureStorageError'
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    // Note: Error.captureStackTrace is V8-specific (Node.js, Chrome). In React Native,
    // this will typically work on Android (V8) but may not work on iOS (JavaScriptCore).
    // If unavailable, the standard Error stack trace will be used instead.
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor)
    }
  }
}

/**
 * Error thrown when keychain operations fail
 * 
 * Note: This is a base error class for completeness. In practice, use
 * KeychainWriteError or KeychainReadError for more specific error handling.
 */
export class KeychainError extends SecureStorageError {
  constructor(message: string, cause?: Error) {
    super(message, 'KEYCHAIN_ERROR', cause)
    this.name = 'KeychainError'
  }
}

/**
 * Error thrown when keychain write operations fail
 */
export class KeychainWriteError extends SecureStorageError {
  constructor(message: string, cause?: Error) {
    super(message, 'KEYCHAIN_WRITE_ERROR', cause)
    this.name = 'KeychainWriteError'
  }
}

/**
 * Error thrown when keychain read operations fail
 */
export class KeychainReadError extends SecureStorageError {
  constructor(message: string, cause?: Error) {
    super(message, 'KEYCHAIN_READ_ERROR', cause)
    this.name = 'KeychainReadError'
  }
}

/**
 * Error thrown when authentication fails or is required but unavailable
 */
export class AuthenticationError extends SecureStorageError {
  constructor(message: string, cause?: Error) {
    super(message, 'AUTHENTICATION_ERROR', cause)
    this.name = 'AuthenticationError'
  }
}

/**
 * Error thrown when input validation fails
 */
export class ValidationError extends SecureStorageError {
  constructor(message: string) {
    super(message, 'VALIDATION_ERROR')
    this.name = 'ValidationError'
  }
}

/**
 * Error thrown when an operation times out
 */
export class TimeoutError extends SecureStorageError {
  constructor(message: string) {
    super(message, 'TIMEOUT_ERROR')
    this.name = 'TimeoutError'
  }
}

/**
 * Error thrown when device security (PIN/pattern/password/biometrics) is not enabled
 * 
 * This error can be used by apps that want to enforce device security as a prerequisite.
 * Whether to require device security is up to the app - the library will still function
 * on devices without authentication configured (data remains encrypted at rest).
 */
export class DeviceSecurityNotEnabledError extends SecureStorageError {
  constructor(message: string = 'Device security is not enabled. Please set up a PIN, pattern, or password in your device settings to use secure wallet storage.', cause?: Error) {
    super(message, 'DEVICE_SECURITY_NOT_ENABLED', cause)
    this.name = 'DeviceSecurityNotEnabledError'
  }
}
