/**
 * Common type definitions for the OTP project
 */

/**
 * Supported OTP algorithms
 */
export type OTPAlgorithm = 'SHA1' | 'SHA256' | 'SHA512';

/**
 * Supported secret lengths in bytes
 */
export type SecretLength = 20 | 32 | 64;

/**
 * OTP configuration interface
 */
export interface OTPConfig {
  readonly secret: string;
  readonly algorithm: OTPAlgorithm;
  readonly digits: number;
  readonly period?: number;
  readonly counter?: number;
}

/**
 * TOTP (Time-based OTP) specific configuration
 */
export interface TOTPConfig extends Omit<OTPConfig, 'counter'> {
  readonly period: number;
}

/**
 * HOTP (HMAC-based OTP) specific configuration
 */
export interface HOTPConfig extends Omit<OTPConfig, 'period'> {
  readonly counter: number;
}

/**
 * OTP generation result
 */
export interface OTPResult {
  readonly token: string;
  readonly remainingTime?: number;
  readonly nextCounter?: number;
}

/**
 * OTP validation result
 */
export interface ValidationResult {
  readonly isValid: boolean;
  readonly delta?: number;
  readonly usedCounter?: number;
}

/**
 * Error types for OTP operations
 */
export type OTPError =
  | 'INVALID_SECRET'
  | 'INVALID_ALGORITHM'
  | 'INVALID_DIGITS'
  | 'INVALID_PERIOD'
  | 'INVALID_COUNTER'
  | 'INVALID_TOKEN'
  | 'EXPIRED_TOKEN';

/**
 * Custom error class for OTP operations
 */
export class OTPException extends Error {
  public readonly code: OTPError;

  public constructor(code: OTPError, message: string) {
    super(message);
    this.name = 'OTPException';
    this.code = code;
  }
}
