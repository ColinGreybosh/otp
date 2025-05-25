import { randomBytes } from 'node:crypto';

import * as base32 from 'hi-base32';

import { OTPException, SecretLength } from '../types';

/**
 * Generates a cryptographically secure random secret and returns it as a base32-encoded string
 *
 * @param length - The length of the random secret in bytes (default: 32)
 * @returns A base32-encoded string representing the generated secret
 * @throws {OTPException} When the length parameter is invalid
 *
 * @example
 * ```typescript
 * const secret = generateSecret(); // 32 bytes -> ~52 character base32 string
 * const shortSecret = generateSecret(20); // 20 bytes -> ~33 character base32 string
 * ```
 */
export function generateSecret(length: SecretLength = 32): string {
  if (!Number.isInteger(length) || length <= 0) {
    throw new OTPException(
      'INVALID_SECRET',
      'Secret length must be a positive integer'
    );
  }

  if (![20, 32, 64].includes(length)) {
    throw new OTPException(
      'INVALID_SECRET',
      'Secret length must be 20, 32, or 64 bytes'
    );
  }

  try {
    const randomBuffer = randomBytes(length);
    return base32.encode(randomBuffer);
  } catch (error) {
    throw new OTPException(
      'INVALID_SECRET',
      `Failed to generate secret: ${error instanceof Error ? error.message : 'Unknown error'}`
    );
  }
}

/**
 * Decodes a base32-encoded secret string to a Buffer for use in HMAC operations
 *
 * @param base32Secret - The base32-encoded secret string to decode
 * @returns A Buffer containing the decoded secret bytes
 * @throws {OTPException} When the base32 string is invalid or decoding fails
 *
 * @example
 * ```typescript
 * const secret = 'JBSWY3DPEHPK3PXP';
 * const buffer = decodeSecretForHMAC(secret);
 * // Use buffer with createHmac()
 * ```
 */
export function decodeSecretForHMAC(base32Secret: string): Buffer {
  if (!base32Secret || typeof base32Secret !== 'string') {
    throw new OTPException(
      'INVALID_SECRET',
      'Secret must be a non-empty string'
    );
  }

  // Remove any whitespace and convert to uppercase for consistency
  const cleanSecret = base32Secret.replace(/\s/g, '').toUpperCase();

  // Validate base32 format (only A-Z and 2-7 are valid base32 characters)
  if (!/^[A-Z2-7]+=*$/.test(cleanSecret)) {
    throw new OTPException(
      'INVALID_SECRET',
      'Secret must be a valid base32-encoded string (A-Z, 2-7)'
    );
  }

  try {
    const decodedBytes = base32.decode.asBytes(cleanSecret);
    return Buffer.from(decodedBytes);
  } catch (error) {
    throw new OTPException(
      'INVALID_SECRET',
      `Failed to decode base32 secret: ${error instanceof Error ? error.message : 'Invalid base32 format'}`
    );
  }
}
