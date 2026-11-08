import { createDecipheriv } from 'node:crypto';

export const d = (key: Buffer, iv: Buffer) => createDecipheriv('des-ede3-cbc', key, iv);
