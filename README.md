# OTP (One-Time Password) Library

A comprehensive TypeScript library for generating, validating, and managing one-time passwords (OTP)
for authentication purposes.

## Overview

- **TOTP (Time-based OTP)**: Generate and validate time-based OTPs based on RFC 6238.
- **HOTP (HMAC-based OTP)**: Generate and validate HMAC-based OTPs based on RFC 4226.
- **Customizable**: Configure OTP parameters such as secret, algorithm, digits, period, and counter.

## Usage

```typescript
import { TOTP, HOTP } from 'otp';

// TOTP usage
const totpConfig = {
  secret: 'JBSWY3DPEHPK3PXP',
  algorithm: 'SHA256',
  digits: 6,
  period: 30,
} satisfies TOTPConfig;

const totp = new TOTP(totpConfig);
const token = totp.generate();
const validation = totp.validate(token.token);
```
