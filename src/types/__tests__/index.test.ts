import { describe, expect, it } from '@jest/globals';

import { OTPException } from '../index';

describe('OTPException', () => {
  it('should create exception with code and message', () => {
    const exception = new OTPException('INVALID_SECRET', 'Test message');

    expect(exception).toBeInstanceOf(Error);
    expect(exception).toBeInstanceOf(OTPException);
    expect(exception.name).toBe('OTPException');
    expect(exception.code).toBe('INVALID_SECRET');
    expect(exception.message).toBe('Test message');
  });

  it('should have correct error properties', () => {
    const exception = new OTPException('INVALID_TOKEN', 'Invalid token format');

    expect(exception.code).toBe('INVALID_TOKEN');
    expect(exception.message).toBe('Invalid token format');
    expect(exception.stack).toBeDefined();
  });

  it('should work with all error codes', () => {
    const errorCodes = [
      'INVALID_SECRET',
      'INVALID_ALGORITHM',
      'INVALID_DIGITS',
      'INVALID_PERIOD',
      'INVALID_COUNTER',
      'INVALID_TOKEN',
      'EXPIRED_TOKEN',
    ] as const;

    errorCodes.forEach(code => {
      const exception = new OTPException(code, `Test ${code}`);
      expect(exception.code).toBe(code);
      expect(exception.message).toBe(`Test ${code}`);
    });
  });
});
