import { type OTPAlgorithm, OTPException, type SecretLength } from '../types';

import { decodeSecretForHMAC } from './crypto';

/**
 * Validates if the provided secret is valid for OTP generation
 */
export function validateSecret(secret: string, algorithm: OTPAlgorithm): void {
  if (!secret || typeof secret !== 'string') {
    throw new OTPException(
      'INVALID_SECRET',
      'Secret must be a non-empty string'
    );
  }

  const decodedSecret = decodeSecretForHMAC(secret);

  const expectedLength = getSecretLength(algorithm);
  if (decodedSecret.length !== expectedLength) {
    throw new OTPException(
      'INVALID_SECRET',
      `Secret must be ${expectedLength.toString()} bytes long for ${algorithm} algorithm`
    );
  }
}

/**
 * Returns the expected length of the secret for the given algorithm
 */
export function getSecretLength(algorithm: OTPAlgorithm): SecretLength {
  switch (algorithm) {
    case 'SHA1':
      return 20; // 20 bytes for SHA1
    case 'SHA256':
      return 32; // 32 bytes for SHA256
    case 'SHA512':
      return 64; // 64 bytes for SHA512
    default:
      throw new UnexpectedCaseError(algorithm);
  }
}

class UnexpectedCaseError extends Error {
  constructor(value: never) {
    super(`Unexpected case: ${value as string}`);
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
