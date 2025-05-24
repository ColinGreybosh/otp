import { describe, expect, it, jest } from '@jest/globals';
import * as base32 from 'hi-base32';

import { OTPAlgorithm, OTPException, TOTPConfig } from '../../types';
import { TOTP } from '../totp';

describe('TOTP', () => {
  const validConfig = {
    secret: 'JBSWY3DPEHPK3PXP',
    algorithm: 'SHA256',
    digits: 6,
    period: 30,
  } satisfies TOTPConfig;

  describe('constructor', () => {
    it('should create TOTP instance with valid config', () => {
      expect(() => new TOTP(validConfig)).not.toThrow();
    });

    it('should reject invalid secret', () => {
      expect(() => new TOTP({ ...validConfig, secret: 'short' })).toThrow(
        OTPException
      );
    });

    it('should reject invalid algorithm', () => {
      expect(
        () => new TOTP({ ...validConfig, algorithm: 'MD5' as never })
      ).toThrow(OTPException);
    });

    it('should reject invalid digits', () => {
      expect(() => new TOTP({ ...validConfig, digits: 5 })).toThrow(
        OTPException
      );
    });

    it('should reject invalid period', () => {
      expect(() => new TOTP({ ...validConfig, period: 0 })).toThrow(
        OTPException
      );
    });
  });

  describe('generate', () => {
    it('should generate a token with correct length', () => {
      const totp = new TOTP(validConfig);
      const result = totp.generate();

      expect(result.token).toMatch(/^\d{6}$/);
      expect(result.remainingTime).toBeGreaterThan(0);
      expect(result.remainingTime).toBeLessThanOrEqual(30);
    });

    it('should generate consistent tokens for same timestamp', () => {
      const totp = new TOTP(validConfig);
      const timestamp = 1234567890000; // Fixed timestamp

      const result1 = totp.generate(timestamp);
      const result2 = totp.generate(timestamp);

      expect(result1.token).toBe(result2.token);
      expect(result1.remainingTime).toBe(result2.remainingTime);
    });

    it('should generate different tokens for different time steps', () => {
      const totp = new TOTP(validConfig);
      const timestamp1 = 1234567890000;
      const timestamp2 = timestamp1 + 30000; // Next period

      const result1 = totp.generate(timestamp1);
      const result2 = totp.generate(timestamp2);

      expect(result1.token).not.toBe(result2.token);
    });

    it('should handle different digit lengths', () => {
      const totp6 = new TOTP({ ...validConfig, digits: 6 });
      const totp7 = new TOTP({ ...validConfig, digits: 7 });
      const totp8 = new TOTP({ ...validConfig, digits: 8 });

      const timestamp = 1234567890000;

      expect(totp6.generate(timestamp).token).toMatch(/^\d{6}$/);
      expect(totp7.generate(timestamp).token).toMatch(/^\d{7}$/);
      expect(totp8.generate(timestamp).token).toMatch(/^\d{8}$/);
    });

    it('should handle different algorithms', () => {
      const totpSHA1 = new TOTP({ ...validConfig, algorithm: 'SHA1' });
      const totpSHA256 = new TOTP({ ...validConfig, algorithm: 'SHA256' });
      const totpSHA512 = new TOTP({ ...validConfig, algorithm: 'SHA512' });

      const timestamp = 1234567890000;

      const token1 = totpSHA1.generate(timestamp).token;
      const token256 = totpSHA256.generate(timestamp).token;
      const token512 = totpSHA512.generate(timestamp).token;

      // Different algorithms should produce different tokens
      expect(token1).not.toBe(token256);
      expect(token256).not.toBe(token512);
      expect(token1).not.toBe(token512);
    });
  });

  describe('validate', () => {
    it('should validate correct token', () => {
      const totp = new TOTP(validConfig);
      const timestamp = 1234567890000;
      const result = totp.generate(timestamp);

      const validation = totp.validate(result.token, timestamp);

      expect(validation.isValid).toBe(true);
      expect(validation.delta).toBe(0);
    });

    it('should validate token within window', () => {
      const totp = new TOTP(validConfig);
      const timestamp = 1234567890000;
      const result = totp.generate(timestamp);

      // Test with previous time step
      const validation1 = totp.validate(result.token, timestamp + 30000, 1);
      expect(validation1.isValid).toBe(true);
      expect(validation1.delta).toBe(-1);

      // Test with next time step
      const validation2 = totp.validate(result.token, timestamp - 30000, 1);
      expect(validation2.isValid).toBe(true);
      expect(validation2.delta).toBe(1);
    });

    it('should reject token outside window', () => {
      const totp = new TOTP(validConfig);
      const timestamp = 1234567890000;
      const result = totp.generate(timestamp);

      // Test with time step outside window
      const validation = totp.validate(result.token, timestamp + 60000, 1);
      expect(validation.isValid).toBe(false);
      expect(validation.delta).toBeUndefined();
    });

    it('should reject invalid token format', () => {
      const totp = new TOTP(validConfig);

      expect(() => totp.validate('invalid')).toThrow(OTPException);
      expect(() => totp.validate('12345')).toThrow(OTPException);
      expect(() => totp.validate('1234567')).toThrow(OTPException);
    });

    it('should reject incorrect token', () => {
      const totp = new TOTP(validConfig);
      const timestamp = 1234567890000;

      const validation = totp.validate('000000', timestamp);
      expect(validation.isValid).toBe(false);
    });
  });

  describe('getCurrentTimeStep', () => {
    it('should return correct time step', () => {
      const totp = new TOTP(validConfig);
      const timestamp = 1234567890000;
      const expectedTimeStep = Math.floor(timestamp / 1000 / 30);

      expect(totp.getCurrentTimeStep(timestamp)).toBe(expectedTimeStep);
    });

    it('should use current time when no timestamp provided', () => {
      const totp = new TOTP(validConfig);
      const now = Date.now();
      const expectedTimeStep = Math.floor(now / 1000 / 30);

      // Mock Date.now to ensure consistent test
      const mockNow = jest.spyOn(Date, 'now').mockReturnValue(now);

      expect(totp.getCurrentTimeStep()).toBe(expectedTimeStep);

      mockNow.mockRestore();
    });
  });

  describe('RFC 6238 test vectors', () => {
    // Test vectors from RFC 6238 Appendix B
    // The test token shared secret uses the ASCII string value "12345678901234567890"
    // For different algorithms, the secret is padded to the appropriate length
    const rfcSecrets = {
      SHA1: base32.encode('12345678901234567890', true), // 20 bytes ASCII
      SHA256: base32.encode('12345678901234567890123456789012', true), // 32 bytes ASCII
      SHA512: base32.encode(
        '1234567890123456789012345678901234567890123456789012345678901234',
        true
      ), // 64 bytes ASCII
    };

    const testVectors = [
      {
        time: 59,
        expected: {
          SHA1: '94287082',
          SHA256: '46119246',
          SHA512: '90693936',
        },
      },
      {
        time: 1111111109,
        expected: {
          SHA1: '07081804',
          SHA256: '68084774',
          SHA512: '25091201',
        },
      },
      {
        time: 1111111111,
        expected: {
          SHA1: '14050471',
          SHA256: '67062674',
          SHA512: '99943326',
        },
      },
      {
        time: 1234567890,
        expected: {
          SHA1: '89005924',
          SHA256: '91819424',
          SHA512: '93441116',
        },
      },
      {
        time: 2000000000,
        expected: {
          SHA1: '69279037',
          SHA256: '90698825',
          SHA512: '38618901',
        },
      },
      {
        time: 20000000000,
        expected: {
          SHA1: '65353130',
          SHA256: '77737706',
          SHA512: '47863826',
        },
      },
    ];

    testVectors.forEach(({ time, expected }) => {
      (['SHA1', 'SHA256', 'SHA512'] satisfies OTPAlgorithm[]).forEach(
        algorithm => {
          it(`should generate correct ${algorithm} token for time ${time.toString()}`, () => {
            const rfcConfig = {
              secret: rfcSecrets[algorithm],
              algorithm,
              digits: 8,
              period: 30,
            } satisfies TOTPConfig;

            const totp = new TOTP(rfcConfig);
            const result = totp.generate(time * 1000);
            expect(result.token).toBe(expected[algorithm]);
          });
        }
      );
    });
  });
});
