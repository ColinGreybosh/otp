import { createHmac } from 'node:crypto';

import { describe, expect, it } from '@jest/globals';
import * as base32 from 'hi-base32';

import { OTPException } from '../../types';
import { decodeSecretForHMAC, generateSecret } from '../crypto';

describe('crypto utilities', () => {
  describe('generateSecret', () => {
    it('should generate a base32-encoded secret with default length', () => {
      const secret = generateSecret();

      expect(typeof secret).toBe('string');
      expect(secret.length).toBeGreaterThan(0);
      // Base32 encoding of 32 bytes should be ~52 characters (32 * 8 / 5 = 51.2, rounded up with padding)
      expect(secret.length).toBeGreaterThanOrEqual(50);
      expect(secret.length).toBeLessThanOrEqual(56);
      // Should only contain valid base32 characters
      expect(secret).toMatch(/^[A-Z2-7]+=*$/);
    });

    it('should generate a base32-encoded secret with custom length', () => {
      const secret16 = generateSecret(16);
      const secret64 = generateSecret(64);

      expect(typeof secret16).toBe('string');
      expect(typeof secret64).toBe('string');

      // 16 bytes -> ~26 characters, 64 bytes -> ~103 characters
      expect(secret16.length).toBeGreaterThanOrEqual(25);
      expect(secret16.length).toBeLessThanOrEqual(32);
      expect(secret64.length).toBeGreaterThanOrEqual(100);
      expect(secret64.length).toBeLessThanOrEqual(110);

      // Should only contain valid base32 characters
      expect(secret16).toMatch(/^[A-Z2-7]+=*$/);
      expect(secret64).toMatch(/^[A-Z2-7]+=*$/);
    });

    it('should generate different secrets on each call', () => {
      const secret1 = generateSecret();
      const secret2 = generateSecret();
      const secret3 = generateSecret();

      expect(secret1).not.toBe(secret2);
      expect(secret2).not.toBe(secret3);
      expect(secret1).not.toBe(secret3);
    });

    it('should generate secrets with appropriate entropy', () => {
      const secrets = new Set<string>();
      const iterations = 100;

      for (let i = 0; i < iterations; i++) {
        secrets.add(generateSecret(16));
      }

      // All secrets should be unique (extremely high probability with proper randomness)
      expect(secrets.size).toBe(iterations);
    });

    it('should reject invalid length parameters', () => {
      expect(() => generateSecret(0)).toThrow(OTPException);
      expect(() => generateSecret(-1)).toThrow(OTPException);
      expect(() => generateSecret(1.5)).toThrow(OTPException);
      expect(() => generateSecret(NaN)).toThrow(OTPException);

      expect(() => generateSecret(0)).toThrow(
        'Secret length must be a positive integer'
      );
    });

    it('should reject length parameters that are too small for security', () => {
      expect(() => generateSecret(15)).toThrow(OTPException);
      expect(() => generateSecret(8)).toThrow(OTPException);
      expect(() => generateSecret(1)).toThrow(OTPException);

      expect(() => generateSecret(15)).toThrow(
        'Secret length must be at least 16 bytes for security'
      );
    });

    it('should accept minimum secure length', () => {
      expect(() => generateSecret(16)).not.toThrow();
      const secret = generateSecret(16);
      expect(secret).toMatch(/^[A-Z2-7]+=*$/);
    });
  });

  describe('decodeSecretForHMAC', () => {
    it('should decode valid base32 secrets to Buffer', () => {
      const testSecret = 'JBSWY3DPEHPK3PXP';
      const buffer = decodeSecretForHMAC(testSecret);

      expect(Buffer.isBuffer(buffer)).toBe(true);
      expect(buffer.length).toBeGreaterThan(0);

      // Verify the decoded content matches expected
      const expectedBytes = base32.decode.asBytes(testSecret);
      expect(buffer).toEqual(Buffer.from(expectedBytes));
    });

    it('should handle secrets with padding', () => {
      const secretWithPadding = 'MFRGG43FMZQW4===';
      const buffer = decodeSecretForHMAC(secretWithPadding);

      expect(Buffer.isBuffer(buffer)).toBe(true);
      expect(buffer.length).toBeGreaterThan(0);
    });

    it('should handle secrets with whitespace', () => {
      const secretWithSpaces = ' JBSWY3DP EHPK3PXP ';
      const cleanSecret = 'JBSWY3DPEHPK3PXP';

      const bufferWithSpaces = decodeSecretForHMAC(secretWithSpaces);
      const bufferClean = decodeSecretForHMAC(cleanSecret);

      expect(bufferWithSpaces).toEqual(bufferClean);
    });

    it('should handle lowercase secrets by converting to uppercase', () => {
      const lowercaseSecret = 'jbswy3dpehpk3pxp';
      const uppercaseSecret = 'JBSWY3DPEHPK3PXP';

      const bufferLower = decodeSecretForHMAC(lowercaseSecret);
      const bufferUpper = decodeSecretForHMAC(uppercaseSecret);

      expect(bufferLower).toEqual(bufferUpper);
    });

    it('should work correctly with HMAC operations', () => {
      const secret = generateSecret(32);
      const buffer = decodeSecretForHMAC(secret);
      const testData = 'test message';

      // Should be able to create HMAC without errors
      expect(() => {
        const hmac = createHmac('sha256', buffer);
        hmac.update(testData);
        const digest = hmac.digest();
        expect(Buffer.isBuffer(digest)).toBe(true);
      }).not.toThrow();
    });

    it('should produce consistent results for the same secret', () => {
      const secret = 'JBSWY3DPEHPK3PXP';
      const buffer1 = decodeSecretForHMAC(secret);
      const buffer2 = decodeSecretForHMAC(secret);

      expect(buffer1).toEqual(buffer2);
    });

    it('should reject empty or non-string secrets', () => {
      expect(() => decodeSecretForHMAC('')).toThrow(OTPException);
      expect(() => decodeSecretForHMAC('')).toThrow(
        'Secret must be a non-empty string'
      );

      // Test non-string input (TypeScript won't catch this at runtime)
      expect(() => decodeSecretForHMAC(null as never)).toThrow(OTPException);
      expect(() => decodeSecretForHMAC(undefined as never)).toThrow(
        OTPException
      );
    });

    it('should reject invalid base32 characters', () => {
      expect(() => decodeSecretForHMAC('INVALID0189')).toThrow(OTPException);
      expect(() => decodeSecretForHMAC('HELLO!')).toThrow(OTPException);
      expect(() => decodeSecretForHMAC('test@example')).toThrow(OTPException);

      expect(() => decodeSecretForHMAC('INVALID0189')).toThrow(
        'Secret must be a valid base32-encoded string'
      );
    });

    it('should handle edge cases with malformed base32', () => {
      // Test various malformed base32 strings
      const malformedSecrets = [
        'AAAAA1', // Contains invalid character '1'
        'AAAAA0', // Contains invalid character '0'
        'AAAAA8', // Contains invalid character '8'
        'AAAAA9', // Contains invalid character '9'
      ];

      malformedSecrets.forEach(secret => {
        expect(() => decodeSecretForHMAC(secret)).toThrow(OTPException);
      });
    });

    // Note: Base32 decode error handling test is omitted due to TypeScript strict mode
    // limitations with mocking third-party modules. The error handling code
    // is still present in the implementation and would be tested in integration tests.
  });

  describe('integration tests', () => {
    it('should work together - generate and decode', () => {
      const secret = generateSecret(32);
      const buffer = decodeSecretForHMAC(secret);

      expect(Buffer.isBuffer(buffer)).toBe(true);
      expect(buffer.length).toBe(32);
    });

    it('should work with different secret lengths', () => {
      const lengths = [16, 20, 32, 64];

      lengths.forEach(length => {
        const secret = generateSecret(length);
        const buffer = decodeSecretForHMAC(secret);

        expect(buffer.length).toBe(length);
      });
    });

    it('should produce secrets that work with HMAC-based OTP', () => {
      const secret = generateSecret(20); // Common length for OTP secrets
      const buffer = decodeSecretForHMAC(secret);

      // Simulate TOTP-like HMAC operation
      const timeStep = Math.floor(Date.now() / 1000 / 30);
      const timeBuffer = Buffer.alloc(8);
      timeBuffer.writeUInt32BE(Math.floor(timeStep / 0x100000000), 0);
      timeBuffer.writeUInt32BE(timeStep & 0xffffffff, 4);

      expect(() => {
        const hmac = createHmac('sha1', buffer);
        hmac.update(timeBuffer);
        const hash = hmac.digest();
        expect(Buffer.isBuffer(hash)).toBe(true);
        expect(hash.length).toBe(20); // SHA1 produces 20-byte hash
      }).not.toThrow();
    });
  });
});
