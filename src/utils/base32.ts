import * as base32 from 'hi-base32';

export function encode(bytes: Readonly<Buffer>): string {
  return base32.encode(bytes);
}

export function decode(base32String: string): Readonly<Buffer> {
  return Buffer.from(base32.decode.asBytes(base32String));
}
