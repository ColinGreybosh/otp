import { describe, expect, it } from '@jest/globals';
import * as base32 from 'hi-base32';

import { OTPException } from '@/types';

import {
  validateAlgorithm,
  validateCounter,
  validateDigits,
  validatePeriod,
  validateSecret,
  validateToken,
} from '../validation';

describe('validation utilities', () => {
  describe('validateSecret', () => {
    it('should accept valid secrets', () => {
      expect(() => {
        validateSecret(
          base32.encode(Buffer.from('A'.repeat(20), 'ascii')),
          'SHA1'
        );
      }).not.toThrow();
      expect(() => {
        validateSecret(
          base32.encode(Buffer.from('a'.repeat(32), 'ascii')),
          'SHA256'
        );
      }).not.toThrow();
    });

    it('should reject empty or non-string secrets', () => {
      expect(() => {
        validateSecret('', 'SHA1');
      }).toThrow(OTPException);
      expect(() => {
        validateSecret('', 'SHA1');
      }).toThrow('Secret must be a non-empty string');
    });

    it('should reject secrets that are too short', () => {
      expect(() => {
        validateSecret('short', 'SHA1');
      }).toThrow(OTPException);
      expect(() => {
        validateSecret('a'.repeat(15), 'SHA1');
      }).toThrow('Secret must be 20 bytes long for SHA1 algorithm');
    });
  });

  describe('validateAlgorithm', () => {
    it('should accept valid algorithms', () => {
      expect(() => {
        validateAlgorithm('SHA1');
      }).not.toThrow();
      expect(() => {
        validateAlgorithm('SHA256');
      }).not.toThrow();
      expect(() => {
        validateAlgorithm('SHA512');
      }).not.toThrow();
    });

    it('should reject invalid algorithms', () => {
      expect(() => {
        validateAlgorithm('MD5');
      }).toThrow(OTPException);
      expect(() => {
        validateAlgorithm('invalid');
      }).toThrow('Algorithm must be one of: SHA1, SHA256, SHA512');
      expect(() => {
        validateAlgorithm('');
      }).toThrow(OTPException);
    });
  });

  describe('validateDigits', () => {
    it('should accept valid digit counts', () => {
      expect(() => {
        validateDigits(6);
      }).not.toThrow();
      expect(() => {
        validateDigits(7);
      }).not.toThrow();
      expect(() => {
        validateDigits(8);
      }).not.toThrow();
    });

    it('should reject invalid digit counts', () => {
      expect(() => {
        validateDigits(5);
      }).toThrow(OTPException);
      expect(() => {
        validateDigits(9);
      }).toThrow(OTPException);
      expect(() => {
        validateDigits(6.5);
      }).toThrow('Digits must be an integer between 6 and 8');
      expect(() => {
        validateDigits(-1);
      }).toThrow(OTPException);
    });
  });

  describe('validatePeriod', () => {
    it('should accept valid periods', () => {
      expect(() => {
        validatePeriod(30);
      }).not.toThrow();
      expect(() => {
        validatePeriod(60);
      }).not.toThrow();
      expect(() => {
        validatePeriod(1);
      }).not.toThrow();
    });

    it('should reject invalid periods', () => {
      expect(() => {
        validatePeriod(0);
      }).toThrow(OTPException);
      expect(() => {
        validatePeriod(-1);
      }).toThrow(OTPException);
      expect(() => {
        validatePeriod(30.5);
      }).toThrow('Period must be a positive integer');
    });
  });

  describe('validateCounter', () => {
    it('should accept valid counters', () => {
      expect(() => {
        validateCounter(0);
      }).not.toThrow();
      expect(() => {
        validateCounter(1);
      }).not.toThrow();
      expect(() => {
        validateCounter(1000);
      }).not.toThrow();
    });

    it('should reject invalid counters', () => {
      expect(() => {
        validateCounter(-1);
      }).toThrow(OTPException);
      expect(() => {
        validateCounter(1.5);
      }).toThrow('Counter must be a non-negative integer');
    });
  });

  describe('validateToken', () => {
    it('should accept valid tokens', () => {
      expect(() => {
        validateToken('123456', 6);
      }).not.toThrow();
      expect(() => {
        validateToken('1234567', 7);
      }).not.toThrow();
      expect(() => {
        validateToken('12345678', 8);
      }).not.toThrow();
    });

    it('should reject empty or non-string tokens', () => {
      expect(() => {
        validateToken('', 6);
      }).toThrow(OTPException);
      expect(() => {
        validateToken('', 6);
      }).toThrow('Token must be a non-empty string');
    });

    it('should reject tokens with non-digit characters', () => {
      expect(() => {
        validateToken('12345a', 6);
      }).toThrow(OTPException);
      expect(() => {
        validateToken('12345a', 6);
      }).toThrow('Token must contain only digits');
    });

    it('should reject tokens with wrong length', () => {
      expect(() => {
        validateToken('12345', 6);
      }).toThrow(OTPException);
      expect(() => {
        validateToken('1234567', 6);
      }).toThrow('Token must be exactly 6 digits long');
    });
  });
});
