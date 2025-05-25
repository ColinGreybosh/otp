# OTP Library

A comprehensive TypeScript library for generating, validating, and managing one-time passwords (OTP)
for authentication purposes.

## Features

- **TOTP (Time-based OTP)**: Generate and validate time-based OTPs based on RFC 6238
- **HOTP (HMAC-based OTP)**: Generate and validate HMAC-based OTPs based on RFC 4226
- **Multiple algorithms**: Support for SHA1, SHA256, and SHA512
- **Customizable**: Configure OTP parameters such as secret, algorithm, digits, period, and counter
- **TypeScript**: Full TypeScript support with comprehensive type definitions
- **Secure**: Cryptographically secure secret generation using Node.js crypto module
- **RFC compliant**: Implements RFC 6238 (TOTP) and RFC 4226 (HOTP) specifications

## Installation

```bash
npm install @colingreybosh/otp-lib
```

## Quick Start

```typescript
import { TOTP, generateSecret } from '@colingreybosh/otp-lib';

// Generate a secure secret
const secret = generateSecret();

// Create TOTP instance
const totp = new TOTP({
  secret,
  algorithm: 'SHA256',
  digits: 6,
  period: 30,
});

// Generate a token
const token = totp.generate();
console.log(`Current token: ${token.token}`);

// Validate a token
const validation = totp.validate(token.token);
console.log(`Valid: ${validation.valid}`);
```
