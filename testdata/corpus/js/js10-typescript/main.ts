import * as crypto from 'crypto';

const k: string = 'aes-128-cbc';
export function enc(key: Buffer, iv: Buffer) {
  return crypto.createCipheriv(k, key, iv);
}
export const h = crypto.createHash('sha512');
