import { beforeEach, describe, expect, it, jest } from '@jest/globals';

// eslint-disable-next-line import/order
import { OTPException } from '../../types';

// Mock the crypto module
const mockRandomBytes = jest.fn();
jest.mock('node:crypto', () => {
  const actual = jest.requireActual('node:crypto');
  return {
    randomBytes: mockRandomBytes,
    createHmac: (actual as typeof import('node:crypto')).createHmac,
  };
});

// Mock the base32 module
const mockBase32Encode = jest.fn();
const mockBase32Decode = jest.fn();
jest.mock('../base32', () => ({
  encode: mockBase32Encode,
  decode: mockBase32Decode,
}));

// Import after mocking
import { decodeSecretForHMAC, generateSecret } from '../crypto';

describe('crypto utilities - error handling', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('generateSecret error handling', () => {
    it('should handle randomBytes errors', () => {
      const error = new Error('Random bytes generation failed');
      mockRandomBytes.mockImplementation(() => {
        throw error;
      });

      expect(() => generateSecret(32)).toThrow(OTPException);
      expect(() => generateSecret(32)).toThrow(
        'Failed to generate secret: Random bytes generation failed'
      );
    });

    it('should handle base32 encoding errors', () => {
      const mockBuffer = Buffer.from('test');
      mockRandomBytes.mockReturnValue(mockBuffer);

      const error = new Error('Base32 encoding failed');
      mockBase32Encode.mockImplementation(() => {
        throw error;
      });

      expect(() => generateSecret(32)).toThrow(OTPException);
      expect(() => generateSecret(32)).toThrow(
        'Failed to generate secret: Base32 encoding failed'
      );
    });

    it('should handle unknown errors in randomBytes', () => {
      mockRandomBytes.mockImplementation(() => {
        throw 'Unknown error type' as unknown;
      });

      expect(() => generateSecret(32)).toThrow(OTPException);
      expect(() => generateSecret(32)).toThrow(
        'Failed to generate secret: Unknown error'
      );
    });

    it('should handle unknown errors in base32 encoding', () => {
      const mockBuffer = Buffer.from('test');
      mockRandomBytes.mockReturnValue(mockBuffer);

      mockBase32Encode.mockImplementation(() => {
        throw 'Unknown error type' as unknown;
      });

      expect(() => generateSecret(32)).toThrow(OTPException);
      expect(() => generateSecret(32)).toThrow(
        'Failed to generate secret: Unknown error'
      );
    });
  });

  describe('decodeSecretForHMAC error handling', () => {
    it('should handle base32 decoding errors', () => {
      const error = new Error('Invalid base32 format');
      mockBase32Decode.mockImplementation(() => {
        throw error;
      });

      expect(() => decodeSecretForHMAC('VALIDFORMAT')).toThrow(OTPException);
      expect(() => decodeSecretForHMAC('VALIDFORMAT')).toThrow(
        'Failed to decode base32 secret: Invalid base32 format'
      );
    });

    it('should handle unknown errors in base32 decoding', () => {
      mockBase32Decode.mockImplementation(() => {
        throw 'Unknown error type' as unknown;
      });

      expect(() => decodeSecretForHMAC('VALIDFORMAT')).toThrow(OTPException);
      expect(() => decodeSecretForHMAC('VALIDFORMAT')).toThrow(
        'Failed to decode base32 secret: Invalid base32 format'
      );
    });

    it('should handle null errors in base32 decoding', () => {
      mockBase32Decode.mockImplementation(() => {
        throw null as unknown;
      });

      expect(() => decodeSecretForHMAC('VALIDFORMAT')).toThrow(OTPException);
      expect(() => decodeSecretForHMAC('VALIDFORMAT')).toThrow(
        'Failed to decode base32 secret: Invalid base32 format'
      );
    });
  });
});
