import { createHmac } from 'node:crypto';

import {
  validateAlgorithm,
  validateCounter,
  validateDigits,
  validatePeriod,
  validateSecret,
  validateToken,
} from '@/utils/validation';

import type { OTPResult, TOTPConfig, ValidationResult } from '@/types';

/**
 * Time-based One-Time Password (TOTP) implementation
 * Based on RFC 6238: https://tools.ietf.org/html/rfc6238
 */
export class TOTP {
  private readonly config: TOTPConfig;

  public constructor(config: TOTPConfig) {
    this.validateConfig(config);
    this.config = { ...config };
  }

  /**
   * Generates a TOTP token for the current time
   */
  public generate(timestamp?: number): OTPResult {
    const currentTime = timestamp ?? Date.now();
    const timeStep = Math.floor(currentTime / 1000 / this.config.period);
    const token = this.generateToken(timeStep);
    const remainingTime =
      this.config.period - ((currentTime / 1000) % this.config.period);

    return {
      token,
      remainingTime: Math.ceil(remainingTime),
    };
  }

  /**
   * Validates a TOTP token against the current time
   */
  public validate(
    token: string,
    timestamp?: number,
    window: number = 1
  ): ValidationResult {
    validateToken(token, this.config.digits);

    const currentTime = timestamp ?? Date.now();
    const currentTimeStep = Math.floor(currentTime / 1000 / this.config.period);

    // Check current time step and surrounding window
    for (let i = -window; i <= window; i++) {
      const timeStep = currentTimeStep + i;
      const expectedToken = this.generateToken(timeStep);

      if (this.constantTimeEquals(token, expectedToken)) {
        return {
          isValid: true,
          delta: i,
        };
      }
    }

    return {
      isValid: false,
    };
  }

  /**
   * Gets the current time step
   */
  public getCurrentTimeStep(timestamp?: number): number {
    const currentTime = timestamp ?? Date.now();
    return Math.floor(currentTime / 1000 / this.config.period);
  }

  /**
   * Validates the TOTP configuration
   */
  private validateConfig(config: TOTPConfig): void {
    validateSecret(config.secret);
    validateAlgorithm(config.algorithm);
    validateDigits(config.digits);
    validatePeriod(config.period);
  }

  /**
   * Generates a token for a specific time step
   */
  private generateToken(timeStep: number): string {
    validateCounter(timeStep);

    const timeBuffer = this.createTimeBuffer(timeStep);
    const hash = this.generateHMAC(timeBuffer);
    const truncatedHash = this.performDynamicTruncation(hash);

    // Generate token with specified number of digits
    const token = truncatedHash % Math.pow(10, this.config.digits);
    return token.toString().padStart(this.config.digits, '0');
  }

  /**
   * Creates a time buffer for the given time step
   */
  private createTimeBuffer(timeStep: number): Buffer {
    const timeBuffer = Buffer.alloc(8);
    timeBuffer.writeUInt32BE(Math.floor(timeStep / 0x100000000), 0);
    timeBuffer.writeUInt32BE(timeStep & 0xffffffff, 4);
    return timeBuffer;
  }

  /**
   * Generates HMAC for the given buffer
   */
  private generateHMAC(timeBuffer: Readonly<Buffer>): Buffer {
    const hmac = createHmac(
      this.config.algorithm.toLowerCase(),
      this.config.secret
    );
    hmac.update(timeBuffer);
    return hmac.digest();
  }

  /**
   * Performs dynamic truncation on the hash
   */
  private performDynamicTruncation(hash: Readonly<Buffer>): number {
    const lastByte = hash[hash.length - 1];
    if (lastByte === undefined) {
      throw new Error('Hash generation failed');
    }

    const offset = lastByte & 0x0f;

    // Ensure we have enough bytes for truncation
    if (hash.length < offset + 4) {
      throw new Error('Invalid hash offset for truncation');
    }

    const [byte0, byte1, byte2, byte3] = [
      hash[offset],
      hash[offset + 1],
      hash[offset + 2],
      hash[offset + 3],
    ];

    if (
      byte0 === undefined ||
      byte1 === undefined ||
      byte2 === undefined ||
      byte3 === undefined
    ) {
      throw new Error('Invalid hash bytes for truncation');
    }

    return (
      ((byte0 & 0x7f) << 24) |
      ((byte1 & 0xff) << 16) |
      ((byte2 & 0xff) << 8) |
      (byte3 & 0xff)
    );
  }

  /**
   * Constant time string comparison to prevent timing attacks
   */
  private constantTimeEquals(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false;
    }

    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }

    return result === 0;
  }
}
