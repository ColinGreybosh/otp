/**
 * OTP (One-Time Password) Library
 *
 * A comprehensive TypeScript library for generating, validating, and managing
 * one-time passwords (OTP) for authentication purposes.
 *
 * @author Colin Greybosh
 * @version 1.0.0
 */

// Export types
export type {
  HOTPConfig,
  OTPAlgorithm,
  OTPConfig,
  OTPResult,
  TOTPConfig,
  ValidationResult,
} from './types';

// Export classes and exceptions
export { OTPException } from './types';

// Export TOTP implementation
export { TOTP } from './lib/totp';

// Export utility functions
export {
  validateAlgorithm,
  validateCounter,
  validateDigits,
  validatePeriod,
  validateSecret,
  validateToken,
} from './utils/validation';

// Export crypto utility functions
export { generateSecret } from './utils/crypto';

// Default export for convenience
export { TOTP as default } from './lib/totp';
