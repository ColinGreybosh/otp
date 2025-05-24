import { type OTPAlgorithm, OTPException } from '@/types';

/**
 * Validates if the provided secret is valid for OTP generation
 */
export function validateSecret(secret: string): void {
  if (!secret || typeof secret !== 'string') {
    throw new OTPException(
      'INVALID_SECRET',
      'Secret must be a non-empty string'
    );
  }

  if (secret.length < 16) {
    throw new OTPException(
      'INVALID_SECRET',
      'Secret must be at least 16 characters long'
    );
  }
}

/**
 * Validates if the provided algorithm is supported
 */
export function validateAlgorithm(
  algorithm: string
): asserts algorithm is OTPAlgorithm {
  const validAlgorithms: readonly OTPAlgorithm[] = ['SHA1', 'SHA256', 'SHA512'];

  if (!validAlgorithms.includes(algorithm as OTPAlgorithm)) {
    throw new OTPException(
      'INVALID_ALGORITHM',
      `Algorithm must be one of: ${validAlgorithms.join(', ')}`
    );
  }
}

/**
 * Validates if the provided digits count is valid
 */
export function validateDigits(digits: number): void {
  if (!Number.isInteger(digits) || digits < 6 || digits > 8) {
    throw new OTPException(
      'INVALID_DIGITS',
      'Digits must be an integer between 6 and 8'
    );
  }
}

/**
 * Validates if the provided period is valid for TOTP
 */
export function validatePeriod(period: number): void {
  if (!Number.isInteger(period) || period <= 0) {
    throw new OTPException(
      'INVALID_PERIOD',
      'Period must be a positive integer'
    );
  }
}

/**
 * Validates if the provided counter is valid for HOTP
 */
export function validateCounter(counter: number): void {
  if (!Number.isInteger(counter) || counter < 0) {
    throw new OTPException(
      'INVALID_COUNTER',
      'Counter must be a non-negative integer'
    );
  }
}

/**
 * Validates if the provided token format is correct
 */
export function validateToken(token: string, expectedLength: number): void {
  if (!token || typeof token !== 'string') {
    throw new OTPException('INVALID_TOKEN', 'Token must be a non-empty string');
  }

  if (!/^\d+$/.test(token)) {
    throw new OTPException('INVALID_TOKEN', 'Token must contain only digits');
  }

  if (token.length !== expectedLength) {
    throw new OTPException(
      'INVALID_TOKEN',
      `Token must be exactly ${expectedLength.toString()} digits long`
    );
  }
}
