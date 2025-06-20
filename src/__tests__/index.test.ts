import { describe, expect, it } from '@jest/globals';
import * as base32 from 'hi-base32';

import {
  generateSecret,
  OTPException,
  TOTP,
  validateAlgorithm,
  validateCounter,
  validateDigits,
  validatePeriod,
  validateSecret,
  validateToken,
} from '../index';

describe('index exports', () => {
  it('should export TOTP class', () => {
    expect(TOTP).toBeDefined();
    expect(typeof TOTP).toBe('function');
  });

  it('should export OTPException class', () => {
    expect(OTPException).toBeDefined();
    expect(typeof OTPException).toBe('function');
  });

  it('should export validation functions', () => {
    expect(validateSecret).toBeDefined();
    expect(typeof validateSecret).toBe('function');

    expect(validateAlgorithm).toBeDefined();
    expect(typeof validateAlgorithm).toBe('function');

    expect(validateDigits).toBeDefined();
    expect(typeof validateDigits).toBe('function');

    expect(validatePeriod).toBeDefined();
    expect(typeof validatePeriod).toBe('function');

    expect(validateCounter).toBeDefined();
    expect(typeof validateCounter).toBe('function');

    expect(validateToken).toBeDefined();
    expect(typeof validateToken).toBe('function');
  });

  it('should allow creating TOTP instance from exports', () => {
    const config = {
      secret: base32.encode(Buffer.from('A'.repeat(20), 'ascii')),
      algorithm: 'SHA1' as const,
      digits: 6,
      period: 30,
    };

    expect(() => new TOTP(config)).not.toThrow();
  });

  it('should allow using validation functions from exports', () => {
    expect(() => {
      validateSecret(
        base32.encode(Buffer.from('A'.repeat(20), 'ascii')),
        'SHA1'
      );
    }).not.toThrow();
    expect(() => {
      validateAlgorithm('SHA1');
    }).not.toThrow();
    expect(() => {
      validateDigits(6);
    }).not.toThrow();
    expect(() => {
      validatePeriod(30);
    }).not.toThrow();
    expect(() => {
      validateCounter(0);
    }).not.toThrow();
    expect(() => {
      validateToken('123456', 6);
    }).not.toThrow();
  });

  it('should allow creating OTPException from exports', () => {
    const exception = new OTPException('INVALID_SECRET', 'Test message');
    expect(exception).toBeInstanceOf(OTPException);
    expect(exception.code).toBe('INVALID_SECRET');
  });

  it('should export crypto utility functions', () => {
    expect(generateSecret).toBeDefined();
    expect(typeof generateSecret).toBe('function');
  });

  it('should allow using crypto functions from exports', () => {
    expect(() => {
      const secret = generateSecret(20);
      expect(typeof secret).toBe('string');
      expect(secret.length).toBeGreaterThan(0);
    }).not.toThrow();
  });
});
