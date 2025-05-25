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

// Mock the hi-base32 module
const mockBase32Encode = jest.fn();
const mockBase32DecodeAsBytes = jest.fn();
jest.mock('hi-base32', () => ({
  encode: mockBase32Encode,
  decode: {
    asBytes: mockBase32DecodeAsBytes,
  },
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
      mockBase32DecodeAsBytes.mockImplementation(() => {
        throw error;
      });

      expect(() => decodeSecretForHMAC('VALIDFORMAT')).toThrow(OTPException);
      expect(() => decodeSecretForHMAC('VALIDFORMAT')).toThrow(
        'Failed to decode base32 secret: Invalid base32 format'
      );
    });

    it('should handle unknown errors in base32 decoding', () => {
      mockBase32DecodeAsBytes.mockImplementation(() => {
        throw 'Unknown error type' as unknown;
      });

      expect(() => decodeSecretForHMAC('VALIDFORMAT')).toThrow(OTPException);
      expect(() => decodeSecretForHMAC('VALIDFORMAT')).toThrow(
        'Failed to decode base32 secret: Invalid base32 format'
      );
    });

    it('should handle null errors in base32 decoding', () => {
      mockBase32DecodeAsBytes.mockImplementation(() => {
        throw null as unknown;
      });

      expect(() => decodeSecretForHMAC('VALIDFORMAT')).toThrow(OTPException);
      expect(() => decodeSecretForHMAC('VALIDFORMAT')).toThrow(
        'Failed to decode base32 secret: Invalid base32 format'
      );
    });
  });

  describe('successful operations with mocks', () => {
    it('should work when randomBytes and base32.encode succeed', () => {
      const mockBuffer = Buffer.from([1, 2, 3, 4]);
      mockRandomBytes.mockReturnValue(mockBuffer);
      mockBase32Encode.mockReturnValue('AEBAGBA=');

      const result = generateSecret(32);
      expect(result).toBe('AEBAGBA=');
      expect(mockRandomBytes).toHaveBeenCalledWith(32);
      expect(mockBase32Encode).toHaveBeenCalledWith(mockBuffer);
    });

    it('should work when base32.decode.asBytes succeeds', () => {
      const mockBytes = [1, 2, 3, 4];
      mockBase32DecodeAsBytes.mockReturnValue(mockBytes);

      const result = decodeSecretForHMAC('AEBAGBA=');
      expect(Buffer.isBuffer(result)).toBe(true);
      expect(result).toEqual(Buffer.from(mockBytes));
      expect(mockBase32DecodeAsBytes).toHaveBeenCalledWith('AEBAGBA=');
    });
  });
});
