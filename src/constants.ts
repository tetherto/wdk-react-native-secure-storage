/**
 * Timeout constants for keychain operations
 */
export const DEFAULT_TIMEOUT_MS = 30000
export const MIN_TIMEOUT_MS = 1000
export const MAX_TIMEOUT_MS = 5 * 60 * 1000

/**
 * Cache TTL for device authentication availability (5 minutes)
 */
export const DEVICE_AUTH_CACHE_TTL_MS = 5 * 60 * 1000


/**
 * Cache TTL for successful authentication results (30 seconds)
 * This prevents repeated authentication prompts for rapid successive operations
 * while maintaining security with a short grace period.
 */
export const AUTH_RESULT_CACHE_TTL_MS = 30 * 1000

/**
 * Cache TTL for successful authentication results (30 seconds)
 * This prevents repeated authentication prompts for rapid successive operations
 * while maintaining security with a short grace period.
 */
export const AUTH_RESULT_CACHE_TTL_MS = 30 * 1000
